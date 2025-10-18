import os
import re
import math
import networkx as nx
from pyverilog.vparser.parser import parse

# ---------------------------
# Graph Feature Extractor
# ---------------------------
def build_graph_from_ast(ast):
    """Builds a graph representation of Verilog AST."""
    graph = nx.DiGraph()

    def add_node(node, parent=None):
        node_id = id(node)
        graph.add_node(node_id, type=type(node).__name__)
        if parent is not None:
            graph.add_edge(parent, node_id)

        for c in getattr(node, "children", lambda: [])():
            add_node(c, node_id)

    add_node(ast)
    return graph


def extract_graph_features(graph):
    """Extract graph-level structural features."""
    num_nodes = graph.number_of_nodes()
    num_edges = graph.number_of_edges()
    degrees = [d for _, d in graph.degree()]
    avg_degree = sum(degrees) / len(degrees) if degrees else 0
    max_degree = max(degrees) if degrees else 0
    try:
        depth = nx.dag_longest_path_length(graph)
    except Exception:
        depth = 0

    return [num_nodes, num_edges, avg_degree, max_degree, depth]

# ---------------------------
# FSM Features
# ---------------------------
def extract_fsm_features(text):
    states = len(re.findall(r"(parameter|localparam)\s+\w+", text))
    cases = text.count("case")
    nested_ifs = max([len(m) for m in re.findall(r"(if\s*\(.*?\))+", text, re.DOTALL)] or [0])
    return [states, cases, nested_ifs]

# ---------------------------
# Trigger Features
# ---------------------------
def calc_entropy(values):
    """Shannon entropy of a list of values (hex/bin constants)."""
    if not values:
        return 0
    counts = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    probs = [c / len(values) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

def extract_trigger_features(text):
    hex_consts = re.findall(r"[0-9]+'h[0-9a-fA-F]+", text)
    bin_consts = re.findall(r"[0-9]+'b[01]+", text)
    suspicious_cmp = len(re.findall(r"==\s*[0-9]+'h[0-9a-fA-F]+", text))
    entropy_hex = calc_entropy(hex_consts)
    entropy_bin = calc_entropy(bin_consts)
    return [len(hex_consts), len(bin_consts), suspicious_cmp, entropy_hex, entropy_bin]

# ---------------------------
# Naming Features
# ---------------------------
def extract_name_features(text):
    names = re.findall(r"\b\w+\b", text)
    unique_names = len(set(names))
    avg_len = sum(len(n) for n in names) / (len(names) or 1)
    return [unique_names, avg_len]

# ---------------------------
# Regex Heuristic Features
# ---------------------------
def extract_regex_features(text):
    """Regex-based structural + heuristic features."""
    operators = re.findall(r"[&|~^+-/*]", text)
    unique_ops = len(set(operators))
    return [
        text.count("module"),                   # number of modules
        text.count("always"),                   # sequential blocks
        text.count("assign"),                   # continuous assignments
        text.count("if"),                       # control flow
        text.count("case"),                     # case statements
        len(operators),                         # total operators
        unique_ops,                             # operator diversity
        len(re.findall(r"==\s*\d+", text)),     # suspicious constant comparisons
        len(re.findall(r"wire\s+\w+", text)),   # wire declarations
        len(re.findall(r"reg\s+\w+", text)),    # reg declarations
    ]

# ---------------------------
# Main Extractor
# ---------------------------
def extract_with_ast(filepath):
    """Try extracting features with AST + graph analysis."""
    try:
        ast, _ = parse([filepath])
        text = open(filepath, errors="ignore").read()
        graph = build_graph_from_ast(ast)

        return (
            extract_graph_features(graph)
            + extract_regex_features(text)
            + extract_fsm_features(text)
            + extract_trigger_features(text)
            + extract_name_features(text)
        )

    except Exception as e:
        print(f"[AST ERROR] {os.path.basename(filepath)}: {e}")
        return None


def extract_with_regex(filepath):
    """Fallback extractor using only regex features."""
    try:
        text = open(filepath, errors="ignore").read()
        return (
            [0, 0, 0, 0, 0]  # pad graph features
            + extract_regex_features(text)
            + extract_fsm_features(text)
            + extract_trigger_features(text)
            + extract_name_features(text)
        )
    except Exception:
        return [0] * 25  # safe fallback length


def extract_features(filepath):
    """Extract features (AST+graph → fallback regex)."""
    features = extract_with_ast(filepath)
    if features is None:
        features = extract_with_regex(filepath)
    print(f"[OK] {os.path.basename(filepath)} → {features}")
    return features


def extract_features_from_file(filepath, expected_features=25):
    """Wrapper for detect_trojan.py ensuring fixed-length feature vector."""
    features = extract_features(filepath)
    if features is None:
        features = [0] * expected_features

    # Pad or truncate
    if len(features) < expected_features:
        features += [0] * (expected_features - len(features))
    elif len(features) > expected_features:
        features = features[:expected_features]

    return features
