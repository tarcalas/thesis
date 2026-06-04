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
from collections import defaultdict
from maltoolbox.model import Model


class BlueprintToMAL:
    def __init__(self, blueprint_json):
        self.bp = blueprint_json["blueprints"][0]
        #TODO:load the module language from a file
        self.model = Model("generated-model", lang_id="tno-appLang")

        # Input lookup tables
        self.assets = {a["bom-ref"]: a for a in self.bp.get("assets", [])}
        self.actors = {a["bom-ref"]: a for a in self.bp.get("actors", [])}
        self.boundaries = self.bp.get("boundaries", [])

        # MAL objects
        self.mal_assets = {}
        self.identities = {}
        self.privileges = {}
        self.channels = []

        # REQUIRED assumption
        self.noauth_identity = None
        self.nopriv_privilege = None

    # -----------------------------
    # Helpers
    # -----------------------------
    def create_asset(self, name, mal_type):
        return self.model.add_asset(mal_type, name)

    def get_or_create_privilege(self, name):
        if name in self.privileges:
            return self.privileges[name]

        priv = self.create_asset(name, "Privilege")
        self.privileges[name] = priv
        return priv

    # -----------------------------
    # Assumption: NoAuth identity
    # -----------------------------
    def ensure_noauth(self):
        self.noauth_identity = self.create_asset("NoAuth", "Identity")
        self.nopriv_privilege = self.get_or_create_privilege("NoPriv")

        # Link NoAuth → NoPriv
        self.noauth_identity.link("privileges", self.nopriv_privilege)

    # -----------------------------
    # Components → Application / Module
    # -----------------------------
    def build_components(self):
        for aid, a in self.assets.items():
            if a["type"] != "component":
                continue

            tag = a.get("tags", ["module"])[0]

            if tag == "application":
                mal_type = "Application"
            else:
                mal_type = "Module"

            mal_asset = self.create_asset(a["name"], mal_type)
            self.mal_assets[aid] = mal_asset

    # -----------------------------
    # Data + Information
    # -----------------------------
    def build_data(self):
        for aid, a in self.assets.items():
            if a["type"] != "data":
                continue

            tag = a.get("tags", ["data"])[0]

            mal_type = "Data" if tag == "data" else "Information"
            mal_asset = self.create_asset(a["name"], mal_type)

            self.mal_assets[aid] = mal_asset

        # Link Data ↔ Information
        for aid, a in self.assets.items():
            if "parent" not in a:
                continue

            child = self.mal_assets.get(aid)
            parent = self.mal_assets.get(a["parent"])

            if child and parent:
                # Data contains Information
                child.link("data", parent)

    # -----------------------------
    # Identities and Privileges
    # -----------------------------
    def build_identities(self):
        for actor_id, actor in self.actors.items():
            identity = self.create_asset(actor["name"], "Identity")
            self.identities[actor_id] = identity

            # Permissions → privileges
            for perm in actor.get("permissions", []):
                priv = self.get_or_create_privilege(perm)
                identity.link("privileges", priv)

            # Delegation
            for dep in actor.get("delegatedBy", []):
                info = self.mal_assets.get(dep)
                if info:
                    identity.link("information", info)

        # Handle right-equivalent identities
        for actor_id, actor in self.actors.items():
            identity = self.identities[actor_id]

            for prop in actor.get("properties", []):
                if prop["name"] == "right-equivalent":
                    target = self.identities.get(prop["value"])
                    if target:
                        identity.link("rightIdentities", target)

    # -----------------------------
    # Link Module ↔ Identity
    # -----------------------------
    def link_module_identities(self):
        for aid, a in self.assets.items():
            module = self.mal_assets.get(aid)
            if not module:
                continue

            for prop in a.get("properties", []):
                if prop["name"] == "identity":
                    identity = self.identities.get(f"actor-{prop['value']}")
                    if identity:
                        module.link("identity", identity)

    # -----------------------------
    # Hierarchy (Application → Module)
    # -----------------------------
    def build_hierarchy(self):
        for aid, a in self.assets.items():
            if "parent" not in a:
                continue

            child = self.mal_assets.get(aid)
            parent_name = a["parent"]

            # Fix: parent might be a name, not bom-ref
            parent = None
            for k, v in self.assets.items():
                if v["name"] == parent_name or k == parent_name:
                    parent = self.mal_assets.get(k)
                    break

            if child and parent:
                child.link("application", parent)

    # -----------------------------
    # Authenticated Access Channels
    # -----------------------------
    def build_channels(self):
        zone_to_assets = defaultdict(list)

        for aid, a in self.assets.items():
            zone = a.get("zone")
            if zone:
                zone_to_assets[zone].append(aid)

        for boundary in self.boundaries:
            zones = boundary.get("zones", [])

            priv_name = next(
                (p["value"] for p in boundary.get("properties", [])
                 if p["name"] == "priv"),
                "NoPriv"
            )

            priv = self.get_or_create_privilege(priv_name)

            if len(zones) < 2:
                continue

            z1, z2 = zones[0], zones[1]

            for s in zone_to_assets[z1]:
                for r in zone_to_assets[z2]:
                    sender = self.mal_assets.get(s)
                    receiver = self.mal_assets.get(r)

                    if not sender or not receiver:
                        continue

                    # Only connect modules/apps
                    if sender.type not in ["Module", "Application"]:
                        continue
                    if receiver.type not in ["Module", "Application"]:
                        continue

                    name = f"{sender.name} - {receiver.name}"

                    channel = self.create_asset(
                        name,
                        "AuthenticatedAccessChannel"
                    )

                    if sender.type == "Application":
                        channel.link("app", sender)
                    else:
                        channel.link("senderModule", sender)

                    if receiver.type == "Module":
                        channel.link("receiverModule", receiver)

                    channel.link("privilege", priv)

                    self.channels.append(channel)

    # -----------------------------
    # Link channels to modules
    # -----------------------------
    def link_channels(self):
        for ch in self.channels:
            sender = ch.associated_assets.get("senderModule")
            receiver = ch.associated_assets.get("receiverModule")
            app = ch.associated_assets.get("app")

            if sender:
                sender[0].link("outgoingAuthenticationRule", ch)

            if receiver:
                receiver[0].link("incomingAuthenticationRule", ch)

            if app:
                app[0].link("outgoingAuthenticationRule", ch)

    # -----------------------------
    # Run everything
    # -----------------------------
    def build(self):
        self.ensure_noauth()  # IMPORTANT assumption

        self.build_components()
        self.build_data()
        self.build_identities()

        self.link_module_identities()
        self.build_hierarchy()

        self.build_channels()
        self.link_channels()

        return self.model


# -----------------------------
# Entry point
# -----------------------------
def transform(input_file, output_file):
    with open(input_file, "r") as f:
        data = json.load(f)

    converter = BlueprintToMAL(data)
    model = converter.build()

    model.save(output_file)
    print(f"Model saved to {output_file}")

###########################


import json
from maltoolbox.model import Model


class BlueprintToMAL:
    def __init__(self, blueprint_json):
        self.bp = blueprint_json["blueprints"][0]
        self.model = Model("generated-model", lang_id="tno-appLang")

        # Input lookup
        self.assets = {a["bom-ref"]: a for a in self.bp.get("assets", [])}
        self.actors = {a["bom-ref"]: a for a in self.bp.get("actors", [])}
        self.boundaries = self.bp.get("boundaries", [])

        # MAL objects
        self.mal_assets = {}
        self.identities = {}
        self.privileges = {}
        self.zone_to_module = {}
        self.channels = []

        # Assumption-required objects
        self.noauth_identity = None
        self.nopriv_privilege = None

    # --------------------------------------------------
    # Core helpers
    # --------------------------------------------------
    def create_asset(self, name, mal_type):
        return self.model.add_asset(mal_type, name)

    def get_or_create_privilege(self, name):
        if name in self.privileges:
            return self.privileges[name]

        p = self.create_asset(name, "Privilege")
        self.privileges[name] = p
        return p

    # --------------------------------------------------
    # REQUIRED assumption: NoAuth identity
    # --------------------------------------------------
    def ensure_noauth(self):
        self.noauth_identity = self.create_asset("NoAuth", "Identity")
        self.nopriv_privilege = self.get_or_create_privilege("NoPriv")

        self.noauth_identity.link("privileges", self.nopriv_privilege)

    # --------------------------------------------------
    # Components
    # --------------------------------------------------
    def build_components(self):
        for aid, a in self.assets.items():
            if a["type"] != "component":
                continue

            tag = a.get("tags", ["module"])[0]

            mal_type = "Application" if tag == "application" else "Module"

            mal_asset = self.create_asset(a["name"], mal_type)
            self.mal_assets[aid] = mal_asset

            # Map zones → modules (assumption: exactly 1 module per zone)
            if mal_type == "Module":
                zone = a.get("zone")
                if zone:
                    self.zone_to_module[zone] = mal_asset

    # --------------------------------------------------
    # Data + Information
    # --------------------------------------------------
    def build_data(self):
        for aid, a in self.assets.items():
            if a["type"] != "data":
                continue

            tag = a.get("tags", ["data"])[0]
            mal_type = "Data" if tag == "data" else "Information"

            mal_asset = self.create_asset(a["name"], mal_type)
            self.mal_assets[aid] = mal_asset

        # Parent relationship
        #TODO: may be incorrect
        for aid, a in self.assets.items():
            if "parent" not in a:
                continue

            child = self.mal_assets.get(aid)
            parent = self.mal_assets.get(a["parent"])

            if child and parent:
                child.link("data", parent)

    # --------------------------------------------------
    # Identities
    # --------------------------------------------------
    def build_identities(self):
        for actor_id, actor in self.actors.items():
            identity = self.create_asset(actor["name"], "Identity")
            self.identities[actor_id] = identity

            # Permissions → Privileges
            for perm in actor.get("permissions", []):
                priv = self.get_or_create_privilege(perm)
                identity.link("privileges", priv)

            # Delegation → information
            for dep in actor.get("delegatedBy", []):
                info = self.mal_assets.get(dep)
                if info:
                    identity.link("information", info)

        # Right equivalence
        for actor_id, actor in self.actors.items():
            identity = self.identities[actor_id]

            for prop in actor.get("properties", []):
                if prop["name"] == "right-equivalent":
                    target = self.identities.get(prop["value"])
                    if target:
                        identity.link("rightIdentities", target)

    # --------------------------------------------------
    # Module identity assignment
    # --------------------------------------------------
    def link_module_identities(self):
        for aid, a in self.assets.items():
            module = self.mal_assets.get(aid)
            if not module:
                continue

            for prop in a.get("properties", []):
                if prop["name"] == "identity":
                    identity = self.identities.get(f"actor-{prop['value']}")
                    if identity:
                        module.link("identity", identity)

    # --------------------------------------------------
    # App → Module hierarchy
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
                child.link("application", parent)

    # --------------------------------------------------
    # Channels (SIMPLIFIED using your assumption)
    # --------------------------------------------------
    def build_channels(self):
        for boundary in self.boundaries:
            zones = boundary.get("zones", [])
            if len(zones) != 2:
                continue  # guaranteed by assumption

            source_zone = zones[0]
            target_zone = zones[1]

            sender = self.zone_to_module.get(source_zone)
            receiver = self.zone_to_module.get(target_zone)

            if not sender or not receiver:
                continue
            
            #TODO: can there be multiple privileges?
            # Privilege from boundary
            priv_name = next(
                (p["value"] for p in boundary.get("properties", [])
                 if p["name"] == "priv"),
                "NoPriv"
            )

            privilege = self.get_or_create_privilege(priv_name)

            name = f"{sender.name} - {receiver.name}"

            channel = self.create_asset(
                name,
                "AuthenticatedAccessChannel"
            )

            channel.link("senderModule", sender)
            channel.link("receiverModule", receiver)
            channel.link("privilege", privilege)

            self.channels.append(channel)

    # --------------------------------------------------
    # Link channels to modules
    # --------------------------------------------------
    def link_channels(self):
        for ch in self.channels:
            sender = ch.associated_assets.get("senderModule")
            receiver = ch.associated_assets.get("receiverModule")

            if sender:
                sender[0].link("outgoingAuthenticationRule", ch)

            if receiver:
                receiver[0].link("incomingAuthenticationRule", ch)

    # --------------------------------------------------
    # Build whole model
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

    converter = BlueprintToMAL(blueprint)
    model = converter.build()

    model.save(output_file)
    print(f"✅ Model saved to {output_file}")


if __name__ == "__main__":
    transform("blueprint.json", "output.malmodel")


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



def main():
    args = parse_args()

    # Load language file
    lang_file_path = os.path.abspath(args.language)
    network_file_path = os.path.join(lang_file_path, "Network.mal")
    device_file_path = os.path.join(lang_file_path, "Device.mal")
    app_file_path = os.path.join(lang_file_path, "Application.mal")
    models = args.models

    entrypoints = dict()
    capabilities = dict()
    count = dict()

    #assumption: all models have the name abrX.yml
    #assumption: there is exactly one network.yml
    for filename in os.listdir(models):
        name = filename.split(".")[0]
        entrypoints[name] = set()
        capabilities[name] = set()
        count[name] = 0

    eval_list = [(network_file_path, os.path.join(args.models, "network.yml"), args.entrypoints, os.path.join(args.output, "network_" + str(count["network"]) + ".yml"), "orig")]
    count["network"] += 1
    while eval_list != []:
        eval_args = eval_list.pop(0)
        with open(eval_network(*eval_args), "r") as f:
            reduced_graph = yaml.safe_load(f)
        if eval_args[0] == network_file_path:
            process_new_info(0, reduced_graph, entrypoints, eval_args[1].split(".")[0].split("/")[-1], count, eval_list, args.models, eval_args[4], args)
        elif eval_args[0] == device_file_path:
            process_new_info(1, reduced_graph, entrypoints, eval_args[1].split(".")[0].split("/")[-1], count, eval_list, args.models, eval_args[4], args)
        elif eval_args[0] == app_file_path:
                process_new_info(2, reduced_graph, entrypoints, eval_args[1].split(".")[0].split("/")[-1], count, eval_list, args.models, eval_args[4], args)


    

if __name__ == "__main__":
    main()