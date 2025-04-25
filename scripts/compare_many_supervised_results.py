import matplotlib.pyplot as plt

description_only = """
F1 scores per class
Defense Evasion: 0.986682107701216
Discovery: 0.972400513478819
Command and Control: 0.9520661157024793
Privilege Escalation: 0.9466323150533676
Persistence: 0.9442026117926395
Lateral Movement: 0.9287169042769857
Execution: 0.8955987717502559
Credential Access: 0.8481675392670157
Collection: 0.7944162436548223
Impact: 0.6757493188010899
Initial Access: 0.6526867627785059
Exfiltration: 0.6423357664233577
Resource Development: 0.5147058823529411
Reconnaissance: 0.37333333333333335
"""

with_epss = """
F1 scores per class
Defense Evasion: 0.9856448251910165
Discovery: 0.9724182168056447
Command and Control: 0.9556650246305419
Persistence: 0.9502369668246445
Privilege Escalation: 0.9502028771670971
Lateral Movement: 0.9298597194388778
Execution: 0.8948979591836734
Credential Access: 0.8709256844850065
Collection: 0.8095238095238095
Exfiltration: 0.7346938775510204
Impact: 0.6833333333333333
Initial Access: 0.6742138364779874
Resource Development: 0.5815602836879432
Reconnaissance: 0.4
"""

with_cvss = """
F1 scores per class
Defense Evasion: 0.9835572024085225
Discovery: 0.966025641025641
Command and Control: 0.9490968801313628
Privilege Escalation: 0.939785740672331
Persistence: 0.9361870788743559
Lateral Movement: 0.9197969543147209
Execution: 0.8796722990271377
Credential Access: 0.8479381443298969
Collection: 0.7934093789607097
Exfiltration: 0.7567567567567568
Resource Development: 0.6666666666666666
Impact: 0.5899705014749262
Initial Access: 0.5833333333333334
Reconnaissance: 0.42105263157894735
"""

with_cwe = """
F1 scores per class
Defense Evasion: 0.9818476124407446
Discovery: 0.9760459916959437
Command and Control: 0.9516129032258065
Privilege Escalation: 0.9484460694698355
Persistence: 0.9433663366336633
Lateral Movement: 0.9404517453798767
Credential Access: 0.9064039408866995
Execution: 0.8899273104880582
Collection: 0.8283313325330132
Initial Access: 0.6649937264742786
Impact: 0.6575342465753424
Resource Development: 0.6490066225165563
Reconnaissance: 0.4484848484848485
Exfiltration: 0.42735042735042733
"""

with_cpe = """
F1 scores per class
Defense Evasion: 0.9858567122652446
Discovery: 0.9694828140057822
Command and Control: 0.956953642384106
Persistence: 0.9512098373661245
Privilege Escalation: 0.9498525073746312
Lateral Movement: 0.9272727272727272
Execution: 0.8977505112474438
Credential Access: 0.8604954367666232
Collection: 0.7923566878980892
Exfiltration: 0.726027397260274
Initial Access: 0.6442432082794308
Impact: 0.6318681318681318
Resource Development: 0.6153846153846154
Reconnaissance: 0.3611111111111111
"""

fully_extended = """
F1 scores per class
Defense Evasion: 0.9800254012238772
Discovery: 0.9728521239220697
Command and Control: 0.9580645161290322
Privilege Escalation: 0.949028236156949
Lateral Movement: 0.9458631256384066
Persistence: 0.9451676528599605
Credential Access: 0.8939393939393939
Execution: 0.8924843423799582
Collection: 0.8181818181818182
Exfiltration: 0.7482993197278912
Resource Development: 0.6580645161290323
Impact: 0.6573033707865169
Initial Access: 0.6151832460732984
Reconnaissance: 0.3673469387755102
"""

hyperparam_finetuned = """
F1 scores per class
Defense Evasion: 0.9840609840609841
Discovery: 0.9791599871753768
Command and Control: 0.9642857142857143
Privilege Escalation: 0.9510849577050386
Lateral Movement: 0.9497435897435897
Persistence: 0.9486571879936809
Credential Access: 0.9181141439205955
Execution: 0.8994871794871795
Collection: 0.8433734939759037
Exfiltration: 0.810126582278481
Impact: 0.72
Initial Access: 0.6743886743886743
Resource Development: 0.6578947368421053
Reconnaissance: 0.46153846153846156
"""

def parse_f1_scores(text):
    """
    Parse a multi-line string containing 'ClassName: score' lines into a dict.
    """
    scores = {}
    for line in text.strip().splitlines():
        if ":" not in line or line.lower().startswith("f1 scores"):
            continue
        cls, val = line.split(":", 1)
        try:
            scores[cls.strip()] = float(val.strip())
        except ValueError:
            pass
    return scores

def plot_multiple_f1_scores(score_texts, title="F1 Comparison", figsize=(12,6)):
    """
    score_texts: dict[str, str] or dict[str, dict]
      Keys are experiment names, values are either raw text blocks or already-parsed dicts.
    """
    # parse everything
    parsed = {}
    for name, data in score_texts.items():
        parsed[name] = data if isinstance(data, dict) else parse_f1_scores(data)
    
    # find the classes common to all experiments
    common = set.intersection(*(set(d.keys()) for d in parsed.values()))
    common = sorted(common)
    
    # prepare plotting
    plt.figure(figsize=figsize)
    colors = plt.cm.get_cmap('tab10')  # up to 10 distinct colors
    markers = ['o','s','^','D','v','P','X','*','h','+']  # cycle through
    
    for (i, (name, scores)) in enumerate(parsed.items()):
        vals = [scores[c] for c in common]
        plt.plot(common, vals,
                 label=name,
                 marker=markers[i % len(markers)],
                 color=colors(i % 10),
                 linewidth=2)
    
    plt.title(title)
    plt.ylabel("F1 Score")
    plt.xlabel("Class")
    plt.xticks(rotation=45, ha='right')
    plt.ylim(0.3,1.0)
    plt.grid(linestyle='--', alpha=0.5)
    plt.legend(title="Experiment", bbox_to_anchor=(1.05,1), loc="upper left")
    plt.tight_layout()
    plt.show()

# --- Example usage: ---
if __name__ == "__main__":
    runs = {
        "Description Only": description_only,
        "Description + EPSS": with_epss,
        "Description + CVSS": with_cvss,
        "Description + CWE": with_cwe,
        "Description + CPE": with_cpe,
        "Fully Extended": fully_extended,
        "Fully Extended Hyper-param Finetuned": hyperparam_finetuned
    }
    plot_multiple_f1_scores(runs, title="SecRoBERTa F1 per Class Comparison")
