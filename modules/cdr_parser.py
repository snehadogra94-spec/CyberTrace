import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import networkx as nx
import os
import io
import base64

def parse_cdr(filepath):
    try:
        df = pd.read_csv(filepath)
        df.columns = [c.strip().lower() for c in df.columns]

        # Rename columns flexibly
        col_map = {}
        for c in df.columns:
            if 'caller' in c or 'from' in c: col_map[c] = 'caller'
            elif 'receiver' in c or 'to' in c or 'called' in c: col_map[c] = 'receiver'
            elif 'duration' in c: col_map[c] = 'duration'
            elif 'date' in c or 'time' in c: col_map[c] = 'datetime'
        df.rename(columns=col_map, inplace=True)

        results = {}
        results['total_records'] = len(df)
        results['status'] = 'success'

        # Top callers
        if 'caller' in df.columns:
            top_callers = df['caller'].value_counts().head(5)
            results['top_callers'] = top_callers.to_dict()

            # Bar chart of top callers
            fig, ax = plt.subplots(figsize=(8, 4))
            ax.bar(top_callers.index.astype(str), top_callers.values, color='#4fc3f7')
            ax.set_title('Top 5 Callers', color='white')
            ax.set_xlabel('Phone Number', color='white')
            ax.set_ylabel('Number of Calls', color='white')
            ax.tick_params(colors='white', labelsize=7)
            fig.patch.set_facecolor('#0d1427')
            ax.set_facecolor('#111d35')
            buf = io.BytesIO()
            plt.savefig(buf, format='png', bbox_inches='tight')
            buf.seek(0)
            results['chart_callers'] = base64.b64encode(buf.read()).decode('utf-8')
            plt.close()

        # Network graph
        if 'caller' in df.columns and 'receiver' in df.columns:
            G = nx.DiGraph()
            for _, row in df.iterrows():
                G.add_edge(str(row['caller']), str(row['receiver']))

            fig, ax = plt.subplots(figsize=(8, 5))
            fig.patch.set_facecolor('#0d1427')
            ax.set_facecolor('#111d35')
            pos = nx.spring_layout(G, seed=42)
            nx.draw_networkx(G, pos, ax=ax,
                node_color='#4fc3f7', node_size=800,
                edge_color='#90caf9', font_size=7,
                font_color='white', arrows=True)
            ax.set_title('Call Network Graph', color='white')
            buf2 = io.BytesIO()
            plt.savefig(buf2, format='png', bbox_inches='tight')
            buf2.seek(0)
            results['chart_network'] = base64.b64encode(buf2.read()).decode('utf-8')
            plt.close()

        return results

    except Exception as e:
        return {'status': 'error', 'message': str(e)}