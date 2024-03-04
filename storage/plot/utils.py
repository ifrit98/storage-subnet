import os
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import plotly.graph_objects as go
from mpl_toolkits.mplot3d import Axes3D

def read_events_into_dataframe(filepath="events_log.json"):
    """Read the events log into a Pandas DataFrame."""
    df = pd.read_json(filepath, lines=True)
    df.set_index('block', inplace=True)

    return df

def load_event_dataframe(filepath=None):
    """Load the events log into a DataFrame."""
    if filepath is None:
        filepath = os.path.join(
            os.path.expanduser("~/.bittensor/miners/default/validator/netuid21/core_storage_validator/"),
            "events.json"
        )
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Events log not found at {filepath}")

    df = read_events_into_dataframe(filepath)

    return df

def get_avg_completion_times(events):
    """Get the average completion times for each task."""
    averages = {}
    for (name, row) in events.groupby('task_name'):
        print(name, end=': ')
        times = row['completion_times'].map(lambda x: sum([_ for _ in x if isinstance(_, float)]) / len(x))
        averages[name] = times.mean()
        print(averages[name])

    return averages

def preprocess_data_for_plotting(df, column_name):
    """Expand list columns in the DataFrame for plotting."""
    rows = []
    for block, row in df.iterrows():
        for i in range(len(row[column_name])):
            new_row = row.to_dict()
            new_row[column_name] = new_row[column_name][i]
            if 'uids' in new_row:
                new_row['uid'] = new_row['uids'][i]
            new_row['block'] = block
            rows.append(new_row)
    new_df = pd.DataFrame(rows)
    new_df.set_index('block', inplace=True)

    return new_df

def preprocess_moving_avg_scores(df, column_name="moving_averaged_scores"):
    rows = []
    for block, row in df.iterrows():
        if row[column_name] is None: continue
        for i in range(len(row[column_name])):
            new_row=row.to_dict()
            new_row['block'] = block
        rows.append(new_row)
    new_df = pd.DataFrame(rows)
    new_df.set_index("block", inplace=True)

    return new_df

def plot_scatter_data(df, y_column, title):
    """Plot specified column over blocks as a scatter plot, grouped by UID."""
    fig, ax = plt.subplots(figsize=(10, 6))

    unique_uids = df['uid'].unique()
    colors = plt.cm.jet(np.linspace(0, 1, len(unique_uids)))

    for uid, color in zip(unique_uids, colors):
        subset = df[df['uid'] == uid]
        ax.scatter(subset.index, subset[y_column], label=f'UID {uid}', s=10, color=color)

    ax.set_xlabel('Block')
    ax.set_ylabel(y_column)
    ax.set_title(title)
    ax.legend(markerscale=2)
    plt.savefig(f"{y_column}_over_time_scatter.png")
    print(f"Scatter plot saved as {y_column}_over_time_scatter.png")

def plot_3d_scatter_data(df, y_column, title):
    """Plot specified column over blocks as a 3D scatter plot, with UIDs on another axis."""
    fig = plt.figure(figsize=(10, 7))
    ax = fig.add_subplot(111, projection='3d')

    unique_uids = df['uid'].unique()
    colors = plt.cm.jet(np.linspace(0, 1, len(unique_uids)))

    uid_to_y = {uid: i for i, uid in enumerate(unique_uids)}

    for uid, color in zip(unique_uids, colors):
        subset = df[df['uid'] == uid]
        ys = np.full(len(subset), uid_to_y[uid])
        ax.scatter(subset.index, ys, subset[y_column], label=f'UID {uid}', color=color)

    ax.set_xlabel('Block')
    ax.set_ylabel('UID')
    ax.set_zlabel(y_column)
    ax.set_title(title)
    ax.set_yticks(list(uid_to_y.values()))
    ax.set_yticklabels(list(uid_to_y.keys()))
    ax.legend()
    plt.savefig(f"{y_column}_over_time_3D.png")
    print("3D scatter plot saved as", f"{y_column}_over_time_3D.png")

def plot_3d_scatter_data_interactive(df, y_column, title):
    """Generate an interactive 3D scatter plot of the specified column over blocks."""
    unique_uids = df['uid'].unique()
    colors = plt.cm.jet(np.linspace(0, 1, len(unique_uids)))

    fig = go.Figure()

    uid_to_y = {uid: i for i, uid in enumerate(unique_uids)}

    for uid, color in zip(unique_uids, colors):
        subset = df[df['uid'] == uid]
        color_hex = f'#{int(color[0]*255):02x}{int(color[1]*255):02x}{int(color[2]*255):02x}'
        fig.add_trace(go.Scatter3d(
            x=subset.index, 
            y=[uid_to_y[uid]]*len(subset), 
            z=subset[y_column],
            mode='markers',
            marker=dict(size=5, color=color_hex),
            name=f'UID {uid}'
        ))

    fig.update_layout(
        title=title,
        scene=dict(
            xaxis_title='Block',
            yaxis_title='UID',
            zaxis_title=y_column
        ),
        legend_title="UIDs"
    )
    fig.show()

def plot_3d_scatter_data_interactive_grouped(df, y_column, title_prefix):
    """Generate interactive 3D scatter plots for each task_name group."""
    grouped = df.groupby('task_name')

    for task_name, group in grouped:
        unique_uids = group['uid'].unique()
        # Generate a color map to ensure each UID has a distinct color
        colors = plt.cm.jet(np.linspace(0, 1, len(unique_uids)))

        fig = go.Figure()

        # Create a numerical index for UIDs to plot on y-axis
        uid_to_y = {uid: i for i, uid in enumerate(unique_uids)}

        for uid, color in zip(unique_uids, colors):
            subset = group[group['uid'] == uid]
            # Convert color from RGBA to hex
            color_hex = f'#{int(color[0]*255):02x}{int(color[1]*255):02x}{int(color[2]*255):02x}'
            fig.add_trace(go.Scatter3d(
                x=subset.index, 
                y=[uid_to_y[uid]]*len(subset), 
                z=subset[y_column],
                mode='markers',
                marker=dict(size=5, color=color_hex),
                name=f'UID {uid}'
            ))

        fig.update_layout(
            title=f'{title_prefix} - {task_name}',
            scene=dict(
                xaxis_title='Block',
                yaxis_title='UID',
                zaxis_title=y_column
            ),
            legend_title="UIDs"
        )
        fig.show()

def plot_heatmap_ma_scores(df):
    expanded_scores = pd.DataFrame(df['moving_averaged_scores'].tolist(), index=df.index)
    plt.figure(figsize=(20, 20))
    sns.heatmap(expanded_scores.T, cmap='viridis')
    plt.title('Moving Averaged Scores over Time')
    plt.xlabel('Block Index')
    plt.ylabel('UID')
    plt.savefig("moving_averaged_scores_heatmap.png")
    print("Heatmap of moving averaged scores saved as moving_averaged_scores_heatmap.png")
