import matplotlib.pyplot as plt

def parse_f1_scores(text):
    """
    Parse a multi-line string containing F1 scores per class into a dictionary.
    """
    scores = {}
    # Split the text into lines and process each one.
    for line in text.strip().splitlines():
        # Skip header lines or empty lines.
        if "F1 scores per class" in line or not line.strip():
            continue
        # Split the line at the first colon.
        if ":" in line:
            class_name, score_str = line.split(":", 1)
            try:
                scores[class_name.strip()] = float(score_str.strip())
            except ValueError:
                print(f"Warning: Could not convert {score_str.strip()} to float for class '{class_name.strip()}'")
    return scores

def compare_f1_scores(text1, text2):
    """
    Compare the F1 scores from two different variables.
    """
    scores1 = parse_f1_scores(text1)
    scores2 = parse_f1_scores(text2)
    
    # Identify common classes between both sets of scores.
    common_classes = set(scores1.keys()) & set(scores2.keys())
    
    print("Comparison of F1 Scores:")
    for cls in sorted(common_classes):
        score1 = scores1[cls]
        score2 = scores2[cls]
        diff = score2 - score1
        print(f"{cls}: {score1:.4f} vs {score2:.4f} | Difference: {diff:+.4f}")


def plot_f1_scores(text1, text2, label1, label2):
    """
    Plot a line graph comparing two sets of F1 scores.
    One dataset is plotted in red, other is blue.
    """
    scores1 = parse_f1_scores(text1)
    scores2 = parse_f1_scores(text2)
    
    # Identify common classes and sort them for consistent plotting.
    common_classes = sorted(set(scores1.keys()) & set(scores2.keys()))
    values1 = [scores1[cls] for cls in common_classes]
    values2 = [scores2[cls] for cls in common_classes]
    
    plt.figure(figsize=(10, 6))
    plt.plot(common_classes, values1, marker='o', linestyle='-', color='red', label=label1)
    plt.plot(common_classes, values2, marker='s', linestyle='--', color='blue', label=label2)
    
    plt.xlabel("Attack Classes")
    plt.ylabel("F1 Score")
    plt.title("Comparison of F1 Scores")
    plt.xticks(rotation=45, ha='right')
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.show()

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

extended_cleaned_cpe_product = """
F1 scores per class
Defense Evasion: 0.9790419161676647
Discovery: 0.9735416002550207
Command and Control: 0.9581993569131833
Privilege Escalation: 0.94640234948605
Persistence: 0.94344069128044
Lateral Movement: 0.9426229508196722
Credential Access: 0.8981132075471698
Execution: 0.8901673640167364
Collection: 0.8083538083538083
Impact: 0.6554621848739496
Resource Development: 0.6225165562913907
Initial Access: 0.6168741355463347
Exfiltration: 0.5511811023622047
Reconnaissance: 0.4713375796178344
"""

extended_cleaned_cpe_product_important_os_name = """
F1 scores per class
Defense Evasion: 0.9794646977388094
Discovery: 0.9741131351869607
Command and Control: 0.9502407704654896
Privilege Escalation: 0.9479896717078569
Lateral Movement: 0.9425051334702259
Persistence: 0.9419660481642321
Credential Access: 0.9032258064516129
Execution: 0.8892371995820272
Collection: 0.800982800982801
Exfiltration: 0.7310344827586207
Impact: 0.6900269541778976
Resource Development: 0.6535947712418301
Initial Access: 0.597544338335607
Reconnaissance: 0.41025641025641024
"""

extended_cleaned_cpe_product_remove_cwe = """
F1 scores per class
Defense Evasion: 0.9813506312985057
Discovery: 0.9643992371265099
Command and Control: 0.9549248747913188
Privilege Escalation: 0.9407821229050279
Persistence: 0.9404238304678129
Lateral Movement: 0.9212121212121213
Execution: 0.8842427332993371
Credential Access: 0.8458498023715415
Collection: 0.7787839586028461
Initial Access: 0.6015831134564644
Impact: 0.5515151515151515
Resource Development: 0.5255474452554745
Exfiltration: 0.453781512605042
Reconnaissance: 0.3918918918918919
"""

with_epss = """
F1 scores per class
Defense Evasion: 0.9800668279755732
Discovery: 0.9725590299936184
Command and Control: 0.9533011272141707
Privilege Escalation: 0.943952802359882
Persistence: 0.9435897435897436
Lateral Movement: 0.9415384615384615
Execution: 0.8878406708595388
Credential Access: 0.886107634543179
Collection: 0.8083538083538083
Exfiltration: 0.6950354609929078
Impact: 0.6777777777777778
Resource Development: 0.6357615894039735
Initial Access: 0.6196808510638298
Reconnaissance: 0.445859872611465
"""

simple_cwe_preserve_os = """
F1 scores per class
Defense Evasion: 0.981044845122515
Discovery: 0.9748006379585327
Command and Control: 0.9640522875816994
Persistence: 0.9456995640110979
Privilege Escalation: 0.9452662721893491
Lateral Movement: 0.9390243902439024
Credential Access: 0.8939393939393939
Execution: 0.8894709271870089
Collection: 0.8075471698113208
Resource Development: 0.6666666666666666
Initial Access: 0.6534391534391535
Impact: 0.6149425287356322
Reconnaissance: 0.3870967741935484
Exfiltration: 0.21359223300970873
"""

simple_cwe_clean_cpe = """
F1 scores per class
Defense Evasion: 0.9810929213742218
Discovery: 0.974146185764443
Command and Control: 0.9639344262295082
Lateral Movement: 0.9471544715447154
Persistence: 0.9464922711058263
Privilege Escalation: 0.9453067257945307
Execution: 0.895010395010395
Credential Access: 0.8925831202046036
Collection: 0.8121059268600253
Resource Development: 0.6666666666666666
Initial Access: 0.6397849462365591
Impact: 0.615819209039548
Reconnaissance: 0.4025974025974026
Exfiltration: 0.12244897959183673
"""

preserved_os_with_epss = """
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

preserved_os_with_epss_and_capec = """
F1 scores per class
Defense Evasion: 0.9751021924934968
Discovery: 0.9635930588635591
Persistence: 0.9355400696864111
Privilege Escalation: 0.9312913907284768
Command and Control: 0.9289256198347108
Lateral Movement: 0.9076396807297605
Credential Access: 0.8796433878157504
Execution: 0.860885839051778
Collection: 0.7958115183246073
Resource Development: 0.7114093959731543
Initial Access: 0.5723905723905723
Impact: 0.3229166666666667
Reconnaissance: 0.19402985074626866
Exfiltration: 0.0
"""

preserved_os_with_epss_post_finetuning = """
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

extended_uncleaned_cpe = """
F1 scores per class
Defense Evasion: 0.9794552169898431
Discovery: 0.9719029374201787
Command and Control: 0.9641693811074918
Persistence: 0.942300039793076
Lateral Movement: 0.9418960244648318
Privilege Escalation: 0.9411329137356534
Credential Access: 0.8945362134688691
Execution: 0.8941053729786124
Collection: 0.8020176544766708
Initial Access: 0.6392572944297082
Impact: 0.6312849162011173
Resource Development: 0.5793103448275863
Reconnaissance: 0.3576158940397351
Exfiltration: 0.0
"""

if __name__ == "__main__":
    #print("Comparing Description Only & Extended Cleaned CPE -> Product")
    #compare_f1_scores(description_only, extended_cleaned_cpe_product)
    #print('*'*50)

    #print("Comparing Description Only & Extended Cleaned CPE -> Product & remove cwe")
    #compare_f1_scores(description_only, extended_cleaned_cpe_product_remove_cwe)
    #print('*'*50)
    
    """print("Comparing Description Only & Extended Cleaned CPE -> Product & Windows | Linux | MacOS")
    print('*'*50)
    compare_f1_scores(description_only, extended_cleaned_cpe_product_important_os_name)
    print('*'*50)"""
    
    """print("Comparing Description Extended Cleaned CPE -> Product & Extended Cleaned CPE -> Product & Windows | Linux | MacOS")
    compare_f1_scores(extended_cleaned_cpe_product, extended_cleaned_cpe_product_important_os_name)
    print('*'*50)

    # Plot the two datasets with the specified colors and labels.
    plot_f1_scores(extended_cleaned_cpe_product, extended_cleaned_cpe_product_important_os_name,
                   "Extended Cleaned CPE", "Extended Cleaned CPE (OS Name Preserved)")"""
    
    print("Extended Dataset - Uncleaned CPE vs Cleaned CPE (Preserving OS Name)")
    compare_f1_scores(extended_uncleaned_cpe, extended_cleaned_cpe_product_important_os_name)
    print('*'*50)

    # Plot the two datasets with the specified colors and labels.
    plot_f1_scores(extended_uncleaned_cpe, extended_cleaned_cpe_product_important_os_name,
                   "Uncleaned CPE", "Cleaned CPE (Preserving OS Name)")

    #print("Comparing Description Only -> With EPSS")
    #print('*'*50)
    #compare_f1_scores(description_only, with_epss)
    #print('*'*50)

    """print("Comparing Extended Cleaned Dataset with Simple CWE !preserving OS Name -> Extended Dataset with Simple CWE Preserves OS Name")
    print('*'*50)
    compare_f1_scores(simple_cwe_clean_cpe, simple_cwe_preserve_os)
    print('*'*50)

    # Plot the two datasets with the specified colors and labels.
    plot_f1_scores(simple_cwe_clean_cpe, simple_cwe_preserve_os,
                   "Simple CWE (CPE Cleaned OS Name !Preserved)", "Simple CWE (OS Name Preserved)")"""