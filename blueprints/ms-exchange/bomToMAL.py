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
        lang = LanguageGraph.load_from_file(
            "/workspaces/thesis/mal-langs/Application.mal"
        )

        self.bp = blueprint_json["blueprints"][0]
        self.model = Model("generated-model", lang_graph=lang)

        self.assets = {a["bom-ref"]: a for a in self.bp.get("assets", [])}
        self.actors = {a["bom-ref"]: a for a in self.bp.get("actors", [])}
        self.boundaries = self.bp.get("boundaries", [])

        self.mal_assets = {}
        self.identities = {}
        self.privileges = {}
        self.zone_to_module = {}
        self.channels = []

        self.noauth_identity = None
        self.nopriv_privilege = None

        # Assumptions:
        # - Exactly one application per blueprint
        # - Exactly one module per trust zone
        self.application = None
        self.public_module = None

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
        if asset.type == "Information":
            return asset

        if asset.type == "Data":
            infos = asset.associated_assets.get("information")
            if infos:
                for info in infos:
                    return info

        return None

    # --------------------------------------------------
    # Assumption:
    # NoAuth identity with NoPriv privilege exists
    # --------------------------------------------------
    def ensure_noauth(self):
        self.noauth_identity = self.create_asset(
            "NoAuth",
            "Identity"
        )

        self.nopriv_privilege = self.get_or_create_privilege(
            "NoPriv"
        )

        self.noauth_identity.add_associated_assets(
            "privileges",
            {self.nopriv_privilege}
        )

    # --------------------------------------------------
    # Components
    # --------------------------------------------------
    def build_components(self):
        for aid, asset in self.assets.items():

            if asset["type"] != "component":
                continue

            tag = asset.get("tags", ["module"])[0]

            mal_type = (
                "Application"
                if tag == "application"
                else "Module"
            )

            mal_asset = self.create_asset(
                asset["name"],
                mal_type
            )

            self.mal_assets[aid] = mal_asset

            zone = asset.get("zone")

            if mal_type == "Application":
                self.application = mal_asset

            elif mal_type == "Module":

                if zone:
                    self.zone_to_module[zone] = mal_asset

                if zone == "zone-public":
                    self.public_module = mal_asset
                

    # --------------------------------------------------
    # Data + Information
    # --------------------------------------------------
    def build_data(self):
        for aid, asset in self.assets.items():

            if asset["type"] != "data":
                continue

            tag = asset.get("tags", ["data"])[0]

            mal_type = (
                "Data"
                if tag == "data"
                else "Information"
            )

            mal_asset = self.create_asset(
                asset["name"],
                mal_type
            )

            self.mal_assets[aid] = mal_asset

        for aid, asset in self.assets.items():

            if "parent" not in asset:
                continue

            child = self.mal_assets.get(aid)
            parent = self.mal_assets.get(asset["parent"])

            if not child or not parent:
                continue

            if child.type == "Information" and parent.type == "Data":
                parent.add_associated_assets(
                    "information",
                    {child}
                )

    # --------------------------------------------------
    # Assumption:
    # Owner of data has read and write rights
    # --------------------------------------------------
    def build_data_ownership(self):

        for aid, asset in self.assets.items():

            if asset["type"] != "data":
                continue

            data_asset = self.mal_assets.get(aid)

            if not data_asset:
                continue

            for owner in asset.get("ownership", []):

                module = self.mal_assets.get(owner)

                if not module:
                    continue

                if module.type != "Module":
                    continue

                module.add_associated_assets(
                    "readData",
                    {data_asset}
                )

                module.add_associated_assets(
                    "writtenData",
                    {data_asset}
                )

    # --------------------------------------------------
    # Identities
    # --------------------------------------------------
    def build_identities(self):

        for actor_id, actor in self.actors.items():

            identity = self.create_asset(
                actor["name"],
                "Identity"
            )

            self.identities[actor_id] = identity

            # Assumption:
            # Every identity has NoPriv
            identity.add_associated_assets(
                "privileges",
                {self.nopriv_privilege}
            )

            for perm in actor.get("permissions", []):

                privilege = self.get_or_create_privilege(
                    perm
                )

                identity.add_associated_assets(
                    "privileges",
                    {privilege}
                )

            for dep in actor.get("delegatedBy", []):

                asset = self.mal_assets.get(dep)

                if not asset:
                    continue

                info = self.resolve_information_asset(asset)

                if not info:
                    continue

                identity.add_associated_assets(
                    "information",
                    {info}
                )

        for actor_id, actor in self.actors.items():

            identity = self.identities[actor_id]

            for prop in actor.get("properties", []):

                if prop["name"] != "right-equivalent":
                    continue

                target = self.identities.get(
                    prop["value"]
                )

                if target:
                    identity.add_associated_assets(
                        "rightIdentities",
                        {target}
                    )

    # --------------------------------------------------
    # Module → Identity
    # --------------------------------------------------
    def link_module_identities(self):

        for aid, asset in self.assets.items():

            module = self.mal_assets.get(aid)

            if not module:
                continue

            if module.type != "Module":
                continue

            for prop in asset.get("properties", []):

                if prop["name"] != "identity":
                    continue

                identity = self.identities.get(
                    f"actor-{prop['value']}"
                )

                if identity:
                    module.add_associated_assets(
                        "identity",
                        {identity}
                    )

    # --------------------------------------------------
    # Application → Module
    # --------------------------------------------------
    def build_hierarchy(self):

        for aid, asset in self.assets.items():

            if "parent" not in asset:
                continue

            child = self.mal_assets.get(aid)
            parent = None

            for k, v in self.assets.items():

                if (
                    v["name"] == asset["parent"]
                    or k == asset["parent"]
                ):
                    parent = self.mal_assets.get(k)
                    break

            if not child or not parent:
                continue

            if (
                child.type == "Information"
                and parent.type == "Data"
            ):
                child.add_associated_assets(
                    "data",
                    {parent}
                )

    # --------------------------------------------------
    # Building the supervisor interactions
    # --------------------------------------------------

    def build_supervisor_links(self):

        if not self.application:
            return

        for aid, asset in self.assets.items():

            if asset.get("type") != "component":
                continue

            module = self.mal_assets.get(aid)

            if not module or module.type != "Module":
                continue

            tags = asset.get("tags", [])

            if "interactsWithSupervisor" not in tags:
                continue

            module.add_associated_assets(
                "ranApplication",
                {self.application}
            )

    # --------------------------------------------------
    # Trust boundary channels
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
                (
                    p["value"]
                    for p in boundary.get("properties", [])
                    if p["name"] == "priv"
                ),
                "NoPriv"
            )

            privilege = self.get_or_create_privilege(
                priv_name
            )

            channel = self.create_asset(
                f"{sender.name} - {receiver.name}",
                "AuthenticatedAccessChannel"
            )

            channel.add_associated_assets(
                "senderModule",
                {sender}
            )

            channel.add_associated_assets(
                "receiverModule",
                {receiver}
            )

            channel.add_associated_assets(
                "privilege",
                {privilege}
            )

            self.channels.append(channel)

    # --------------------------------------------------
    # Assumption:
    # Application and module in same trust-zone
    # get a NoPriv AAC
    # --------------------------------------------------
    def build_same_zone_application_channel(self):

        if not self.application:
            return

        app_zone = None

        for aid, asset in self.assets.items():

            if self.mal_assets.get(aid) == self.application:
                app_zone = asset.get("zone")
                break

        if not app_zone:
            return

        module = self.zone_to_module.get(app_zone)

        if not module:
            return

        channel = self.create_asset(
            f"{self.application.name}-{module.name}",
            "AuthenticatedAccessChannel"
        )

        channel.add_associated_assets(
            "receiverModule",
            {module}
        )

        channel.add_associated_assets(
            "privilege",
            {self.nopriv_privilege}
        )

        channel.add_associated_assets(
            "app",
            {self.application}
        )

        self.channels.append(channel)

    # --------------------------------------------------
    # Link channels
    # --------------------------------------------------
    def link_channels(self):

        for channel in self.channels:

            senders = channel.associated_assets.get(
                "senderModule"
            )

            receivers = channel.associated_assets.get(
                "receiverModule"
            )

            if senders:
                for sender in senders:
                    sender.add_associated_assets(
                        "outgoingAuthenticationRule",
                        {channel}
                    )

            if receivers:
                for receiver in receivers:
                    receiver.add_associated_assets(
                        "incomingAuthenticationRule",
                        {channel}
                    )

    # --------------------------------------------------
    # Build model
    # --------------------------------------------------
    def build(self):

        self.ensure_noauth()

        self.build_components()

        self.build_data()
        
        self.build_data_ownership()

        self.build_identities()

        self.link_module_identities()

        self.build_hierarchy()

        self.build_supervisor_links()

        self.build_channels()

        self.build_same_zone_application_channel()

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