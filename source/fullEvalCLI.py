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


def eval_network(lang_file_path, model_file_path, entrypoints, output_path, _):
    my_language = LanguageGraph.load_from_file(lang_file_path)
    # Load model
    model = Model.load_from_file(model_file_path, my_language)

    # Build full attack graph
    graph = AttackGraph(my_language, model)
    graph.save_to_file("full_attack_graph.yml")
    agent_settings = [
        AttackerSettings(
            "attacker",
            entry_points=set(entrypoints),
            goals={},
            policy=BreadthFirstAttacker
        )
    ]
    simulator = MalSimulator(graph, agent_settings, MalSimulatorSettings(
    compromise_entrypoints_at_start = False))
    path = run_simulation(simulator)
    
    #pprint.pprint(simulator.recording)

    path = path['attacker']
    first_ids = {node.id for node in path}

    # Reduce the attack graph
    graph_serialised = graph._to_dict()

    # Find nodes not in attacker path
    second = [
        node for node in graph_serialised['attack_steps']
        if graph_serialised['attack_steps'][node]['id'] not in first_ids
    ]

    # Remove disconnected parents/children
    for node in list(graph_serialised['attack_steps']):
        parents = graph_serialised['attack_steps'][node]['parents']
        children = graph_serialised['attack_steps'][node]['children']

        for parent in list(parents):
            if parent not in first_ids:
                del parents[parent]

        for child in list(children):
            if child not in first_ids:
                del children[child]

    # Remove irrelevant nodes
    for node in second:
        del graph_serialised['attack_steps'][node]

    # Add asset name
    for node in list(graph_serialised['attack_steps']):
        graph_serialised['attack_steps'][node]['asset'] = node.split(":")[0]

    # Build reduced graph
    reduced_attack_graph = attack_graph_from_dict(graph_serialised, my_language, model)
    reduced_attack_graph.save_to_file(output_path)
    return output_path

def process_new_info(type, reduced_graph, entrypoints, current_asset, counts, eval_list, models, invoker, args):
    lang_file_path = os.path.abspath(args.language)
    network_file_path = os.path.join(lang_file_path, "Network.mal")
    device_file_path = os.path.join(lang_file_path, "Device.mal")
    app_file_path = os.path.join(lang_file_path, "Application.mal")
    models = args.models
    to_eval = set()
    for _, node in reduced_graph["attack_steps"].items():
        match type:
            case 0:
                if node["lang_graph_attack_step"] == "Device:physicalAccess":
                    count = len(entrypoints[node["asset"]])
                    entrypoints[node["asset"]].add(node["asset"] + ":hardwarePhysicalAccess")
                    #assumption: every model has a NoAuth identity
                    entrypoints[node["asset"]].add("NoAuth:assumeIdentity")
                    if count < len(entrypoints[node["asset"]]):
                        to_eval.add((node["asset"], "Device"))
                if node["lang_graph_attack_step"] == "Port:connectToPort":
                    #assumption: naming is of "device+port:connectToPort"
                    info = node["asset"].split("+")
                    count = len(entrypoints[info[0]])
                    entrypoints[info[0]].add(info[1] + ":connectToPort")
                    if count < len(entrypoints[info[0]]):
                        to_eval.add((info[0], "Device"))
            case 1:
                if node["lang_graph_attack_step"] == "Application:connectToApp":
                    #assumption: naming is of "app:connectToApp"
                    count = len(entrypoints[node["asset"]])
                    entrypoints[node["asset"]].add(node["asset"] + ":interactWithApplication")
                    #assumption: every model has a NoAuth identity 
                    entrypoints[node["asset"]].add("NoAuth:assumeIdentity")
                    if count < len(entrypoints[node["asset"]]):
                        to_eval.add((node["asset"], "Application"))
                if node["lang_graph_attack_step"] == "Identity:assumeIdentity":
                    #assumption: naming is of "app+identity:assumeIdentity"
                    info = node["asset"].split("+")
                    if len(info) == 2:
                        count = len(entrypoints[info[0]])
                        entrypoints[info[0]].add(info[1] + ":assumeIdentity")
                        if count < len(entrypoints[info[0]]):
                            to_eval.add((info[0], "Application"))
                    else:
                        #if its device wide identity, it might be relevant for the network attack graph
                        count = len(entrypoints["network"])
                        #TODO: need to check whether it actually exists
                        #entrypoints["network"].add(current_asset + "+" + node["asset"] + ":assumeIdentity")
                        if count < len(entrypoints["network"]):
                            to_eval.add(("network", "Network"))
                if node["lang_graph_attack_step"] == "Port:connectToPort":
                    #if no next steps, the communication is on the network level and we can add a network entry point
                    if node["children"] == {}:
                        count = len(entrypoints["network"])
                        entrypoints["network"].add(current_asset + "+" + node["asset"] + ":connectToPort")
                        if count < len(entrypoints["network"]):
                            to_eval.add(("network", "Network"))
                    else:
                        #we need to check if the comm is with an app, if not we can ignore it since we are only interested in entry points for applications
                        for _, value in node["children"].items():
                            info = value.split("-")
                            if info[0] != node["asset"]:
                                continue
                            else:
                                #assumption: the next step of the outgoing comm is always of the form "port-app:attemptAuthenticatedCommunication"
                                info = info[1].split(":")
                                count = len(entrypoints[info[0]])
                                entrypoints[info[0]].add(node["asset"] + ":connectToPort")
                                if count < len(entrypoints[info[0]]):
                                    to_eval.add((info[0], "Application"))
            case 2:
                if node["lang_graph_attack_step"] == "Identity:assumeIdentity":
                    count = len(entrypoints[invoker])
                    #this is very ugly
                    #we check whether the identity exists in the device model
                    identity_exists = False
                    identity_to_add = current_asset + "+" + node["asset"]
                    with open(args.models + "/" + invoker + ".yml", "r") as f:
                        parent = yaml.safe_load(f)
                    for _, value in parent["assets"].items():
                        if value["name"] == identity_to_add:
                            identity_exists = True
                            break
                    if identity_exists:
                        entrypoints[invoker].add(identity_to_add + ":assumeIdentity")
                    if count < len(entrypoints[invoker]):
                        to_eval.add((invoker, "Device"))
                if node["lang_graph_attack_step"] == "Port:connectToPort":
                    #if no next steps, the communication is on the device level and we can add a device entry point
                    if node["children"] == {}:
                        count = len(entrypoints[invoker])
                        entrypoints[invoker].add(current_asset + "-" + node["asset"] + ":connectToPortEntryPoint")
                        if count < len(entrypoints[invoker]):
                            to_eval.add((invoker, "Device")) 
    for (asset, type) in to_eval:
       print(asset, entrypoints[asset])
       match type:
            case "Network":
                eval_list.append((network_file_path, os.path.join(models, asset + ".yml"), entrypoints[asset], os.path.join(args.output, asset + "_" + str(counts[asset]) + ".yml"),current_asset))
                counts[asset] += 1
            case "Device":
                eval_list.append((device_file_path, os.path.join(models, asset + ".yml"), entrypoints[asset], os.path.join(args.output, asset + "_" + str(counts[asset]) + ".yml"),current_asset))
                counts[asset] += 1
            case "Application":
                eval_list.append((app_file_path, os.path.join(models, asset + ".yml"), entrypoints[asset], os.path.join(args.output, asset + "_" + str(counts[asset]) + ".yml"),current_asset))
                counts[asset] += 1

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


    # Optional: Neo4j ingestion
   # ingest_attack_graph_neo4j(
   #     reduced_attack_graph,
   #     {
   #         'uri': 'bolt://neo4j:7687',
   #         'username': 'neo4j',
   #         'password': 'secretgraph',
   #         'dbname': 'neo4j'
   #     }
   # )
    

if __name__ == "__main__":
    main()