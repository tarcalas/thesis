import os
import argparse
import pprint
from maltoolbox.attackgraph import AttackGraph
from maltoolbox.attackgraph.attackgraph import attack_graph_from_dict
from maltoolbox.model import Model
from maltoolbox.language import LanguageGraph
from maltoolbox.visualization import ingest_attack_graph_neo4j
from malsim.mal_simulator import MalSimulator, MalSimulatorSettings, TTCMode, run_simulation
from malsim.config import AttackerSettings, RewardMode
from malsim.policies import BreadthFirstAttacker
from numpy import empty
import yaml

import json
from maltoolbox.model import Model
from maltoolbox.language import LanguageGraph


class BlueprintToMAL:
    def __init__(self, blueprint_json):
        # Load MAL language
        lang = LanguageGraph.load_from_file(
            "/workspaces/thesis/mal-langs/Application.mal"
        )

        self.bp = blueprint_json["blueprints"][0]
        self.model = Model("generated-model", lang_graph=lang)

        # Blueprint lookup tables
        self.assets = {a["bom-ref"]: a for a in self.bp.get("assets", [])}
        self.actors = {a["bom-ref"]: a for a in self.bp.get("actors", [])}
        self.boundaries = self.bp.get("boundaries", [])

        # MAL assets
        self.mal_assets = {}
        self.identities = {}
        self.privileges = {}
        self.zone_to_module = {}
        self.channels = []

        # Required assumption
        self.noauth_identity = None
        self.nopriv_privilege = None

    # --------------------------------------------------
    # Helpers
    # --------------------------------------------------
    def create_asset(self, name, mal_type):
        return self.model.add_asset(mal_type, name)

    def get_or_create_privilege(self, name):
        if name in self.privileges:
            return self.privileges[name]
        priv = self.create_asset(name, "Privilege")
        self.privileges[name] = priv
        return priv

    def resolve_information_asset(self, asset):
        """
        Ensure Identity.information only receives Information assets.
        If a Data asset is given, try to resolve its contained Information.
        """
        if asset.type == "Information":
            return asset

        if asset.type == "Data":
            infos = asset.associated_assets.get("information")
            if infos:
                for info in infos:  # Assuming one Information per Data, this is ugly
                    return info

        return None

    # --------------------------------------------------
    # REQUIRED assumption: NoAuth
    # --------------------------------------------------
    def ensure_noauth(self):
        self.noauth_identity = self.create_asset("NoAuth", "Identity")
        self.nopriv_privilege = self.get_or_create_privilege("NoPriv")
        self.noauth_identity.add_associated_assets(
            "privileges", {self.nopriv_privilege}
        )

    # --------------------------------------------------
    # Components (Application / Module)
    # --------------------------------------------------
    def build_components(self):
        for aid, a in self.assets.items():
            if a["type"] != "component":
                continue

            tag = a.get("tags", ["module"])[0]
            mal_type = "Application" if tag == "application" else "Module"

            mal_asset = self.create_asset(a["name"], mal_type)
            self.mal_assets[aid] = mal_asset

            # Exactly one module per zone
            if mal_type == "Module":
                zone = a.get("zone")
                if zone:
                    self.zone_to_module[zone] = mal_asset

    # --------------------------------------------------
    # Data + Information
    # --------------------------------------------------
    def build_data(self):
        # Create Data / Information assets
        for aid, a in self.assets.items():
            if a["type"] != "data":
                continue

            tag = a.get("tags", ["data"])[0]
            mal_type = "Data" if tag == "data" else "Information"

            mal_asset = self.create_asset(a["name"], mal_type)
            self.mal_assets[aid] = mal_asset

        # DataContainsInformation (CORRECT DIRECTION)
        for aid, a in self.assets.items():
            if "parent" not in a:
                continue

            child = self.mal_assets.get(aid)           # Information
            parent = self.mal_assets.get(a["parent"])  # Data

            if not child or not parent:
                continue

            if child.type == "Information" and parent.type == "Data":
                parent.add_associated_assets("information", {child})

    # --------------------------------------------------
    # Identities + Privileges
    # --------------------------------------------------
    def build_identities(self):
        for actor_id, actor in self.actors.items():
            identity = self.create_asset(actor["name"], "Identity")
            self.identities[actor_id] = identity

            # Permissions → Privileges
            for perm in actor.get("permissions", []):
                priv = self.get_or_create_privilege(perm)
                identity.add_associated_assets("privileges", {priv})

            # Delegation → Information (TYPE SAFE)
            for dep in actor.get("delegatedBy", []):
                asset = self.mal_assets.get(dep)
                if not asset:
                    continue

                info = self.resolve_information_asset(asset)
                if info:
                    identity.add_associated_assets("information", {info})

        # Right-equivalent identities
        for actor_id, actor in self.actors.items():
            identity = self.identities[actor_id]

            for prop in actor.get("properties", []):
                if prop["name"] == "right-equivalent":
                    target = self.identities.get(prop["value"])
                    if target:
                        identity.add_associated_assets(
                            "rightIdentities", {target}
                        )

    # --------------------------------------------------
    # Module → Identity
    # --------------------------------------------------
    def link_module_identities(self):
        for aid, a in self.assets.items():
            module = self.mal_assets.get(aid)
            if not module or module.type != "Module":
                continue

            for prop in a.get("properties", []):
                if prop["name"] == "identity":
                    identity = self.identities.get(f"actor-{prop['value']}")
                    if identity:
                        module.add_associated_assets(
                            "identity", {identity}
                        )

    # --------------------------------------------------
    # Application → Module hierarchy
    # --------------------------------------------------
    def build_hierarchy(self):
        for aid, a in self.assets.items():
            if "parent" not in a:
                continue

            child = self.mal_assets.get(aid)
            parent = None

            for k, v in self.assets.items():
                if v["name"] == a["parent"] or k == a["parent"]:
                    parent = self.mal_assets.get(k)
                    break

            if child and parent:
                if child.type == "Module" and parent.type == "Application":
                    child.add_associated_assets("application", {parent})
                if child.type == "Information" and parent.type == "Data":
                    child.add_associated_assets("data", {parent})

    # --------------------------------------------------
    # Authenticated Access Channels
    # (1 boundary = 1 directed channel)
    # --------------------------------------------------
    def build_channels(self):
        for boundary in self.boundaries:
            zones = boundary.get("zones", [])
            if len(zones) != 2:
                continue

            sender = self.zone_to_module.get(zones[0])
            receiver = self.zone_to_module.get(zones[1])

            if not sender or not receiver:
                continue

            priv_name = next(
                (p["value"] for p in boundary.get("properties", [])
                 if p["name"] == "priv"),
                "NoPriv"
            )

            privilege = self.get_or_create_privilege(priv_name)

            channel = self.create_asset(
                f"{sender.name} - {receiver.name}",
                "AuthenticatedAccessChannel"
            )

            channel.add_associated_assets("senderModule", {sender})
            channel.add_associated_assets("receiverModule", {receiver})
            channel.add_associated_assets("privilege", {privilege})

            self.channels.append(channel)

    # --------------------------------------------------
    # Link channels to modules
    # --------------------------------------------------
    def link_channels(self):
        for ch in self.channels:
            sender = ch.associated_assets.get("senderModule")
            receiver = ch.associated_assets.get("receiverModule")
            
            #TODO: assumes exactly one sender and one receiver
            if sender:
                for s in sender:
                    s.add_associated_assets(
                        "outgoingAuthenticationRule", {ch}
                    )

            if receiver:
                for r in receiver:
                    r.add_associated_assets(
                        "incomingAuthenticationRule", {ch}
                    )

    # --------------------------------------------------
    # Build model
    # --------------------------------------------------
    def build(self):
        self.ensure_noauth()

        self.build_components()
        self.build_data()
        self.build_identities()

        self.link_module_identities()
        self.build_hierarchy()

        self.build_channels()
        self.link_channels()

        return self.model


# --------------------------------------------------
# Entry point
# --------------------------------------------------
def transform(input_file, output_file):
    with open(input_file, "r") as f:
        blueprint = json.load(f)

    model = BlueprintToMAL(blueprint).build()
    model.save_to_file(output_file)
    print(f"✅ Model saved to {output_file}")


if __name__ == "__main__":
    transform(
        "blueprints/ms-exchange/exchange-blue.json",
        "autooutput.yaml"
    )

def parse_args():
    parser = argparse.ArgumentParser(description="Generate and reduce attack graphs using MALSim.")
    
    parser.add_argument(
        "--language",
        required=True,
        help="Path to the .mal language file"
    )
    parser.add_argument(
        "--models",
        required=True,
        help="Path to the model .yml file"
    )
    parser.add_argument(
        "--entrypoints",
        nargs="+",
        required=True,
        help="List of attacker entrypoints (space‑separated)"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to save the reduced attack graph"
    )

    return parser.parse_args()



#def main():
#    args = parse_args()
#
#    # Load language file
#    lang_file_path = os.path.abspath(args.language)
#    network_file_path = os.path.join(lang_file_path, "Network.mal")
#    device_file_path = os.path.join(lang_file_path, "Device.mal")
#    app_file_path = os.path.join(lang_file_path, "Application.mal")
#    models = args.models
#
#    entrypoints = dict()
#    capabilities = dict()
#    count = dict()
#
#    #assumption: all models have the name abrX.yml
#    #assumption: there is exactly one network.yml
#    for filename in os.listdir(models):
#        name = filename.split(".")[0]
#        entrypoints[name] = set()
#        capabilities[name] = set()
#        count[name] = 0
#
#    eval_list = [(network_file_path, os.path.join(args.models, "network.yml"), args.entrypoints, os.path.join(args.output, "network_" + str(count["network"]) + ".yml"), "orig")]
#    count["network"] += 1
#    while eval_list != []:
#        eval_args = eval_list.pop(0)
#        with open(eval_network(*eval_args), "r") as f:
#            reduced_graph = yaml.safe_load(f)
#        if eval_args[0] == network_file_path:
#            process_new_info(0, reduced_graph, entrypoints, eval_args[1].split(".")[0].split("/")[-1], count, eval_list, args.models, eval_args[4], args)
#        elif eval_args[0] == device_file_path:
#            process_new_info(1, reduced_graph, entrypoints, eval_args[1].split(".")[0].split("/")[-1], count, eval_list, args.models, eval_args[4], args)
#        elif eval_args[0] == app_file_path:
#                process_new_info(2, reduced_graph, entrypoints, eval_args[1].split(".")[0].split("/")[-1], count, eval_list, args.models, eval_args[4], args)
#
#
#    
#
#if __name__ == "__main__":
#    main()