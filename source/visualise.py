import os
import argparse
import pprint
from maltoolbox.attackgraph import AttackGraph
from maltoolbox.attackgraph.attackgraph import attack_graph_from_dict
from maltoolbox.model import Model
from maltoolbox.language import LanguageGraph
from maltoolbox.visualization import ingest_attack_graph_neo4j
import yaml 


def main():
    parser = argparse.ArgumentParser(description='Visualise an attack graph in Neo4j')
    parser.add_argument('--attack_graph_path', type=str, help='Path to the attack graph YAML file')
    parser.add_argument('--language_graph_path', type=str, help='Path to the language graph YAML file')
    parser.add_argument('--model_file_path', type=str, help='Path to the model file')
    args = parser.parse_args()

    with open(args.attack_graph_path, 'r') as f:
        attack_graph_dict = yaml.safe_load(f)
    language_graph = LanguageGraph.load_from_file(args.language_graph_path)
    model = Model.load_from_file(args.model_file_path, language_graph)

    attack_graph = attack_graph_from_dict(attack_graph_dict, language_graph, model)
    ingest_attack_graph_neo4j(
        attack_graph,
        {
            'uri': 'bolt://neo4j:7687',
            'username': 'neo4j',
            'password': 'secretgraph',
            'dbname': 'neo4j'
        }
    )

if __name__ == "__main__":
    main()