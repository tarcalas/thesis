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


def parse_args():
    parser = argparse.ArgumentParser(description="Generate and reduce attack graphs using MALSim.")
    
    parser.add_argument(
        "--langfile",
        required=True,
        help="Path to the .mal language file"
    )
    parser.add_argument(
        "--model",
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
    lang_file_path = os.path.abspath(args.langfile)
    my_language = LanguageGraph.load_from_file(lang_file_path)

    # Load model
    model = Model.load_from_file(args.model, my_language)

    # Build full attack graph
    graph = AttackGraph(my_language, model)
    graph.save_to_file("full_attack_graph.yml")

    # Simulator configuration
    agent_settings = [
        AttackerSettings(
            "attacker",
            entry_points=set(args.entrypoints),
            goals={},
            policy=BreadthFirstAttacker
        )
    ]

    simulator = MalSimulator(graph, agent_settings, MalSimulatorSettings(
    compromise_entrypoints_at_start = False))
    path = run_simulation(simulator)
    
    pprint.pprint(simulator.recording)

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
    reduced_attack_graph.save_to_file(args.output)

    # Optional: Neo4j ingestion
    ingest_attack_graph_neo4j(
        reduced_attack_graph,
        {
            'uri': 'bolt://neo4j:7687',
            'username': 'neo4j',
            'password': 'secretgraph',
            'dbname': 'neo4j'
        }
    )


if __name__ == "__main__":
    main()