import argparse

from storage.plot.utils import (
    load_event_dataframe,
    preprocess_data_for_plotting,
    preprocess_moving_avg_scores,
    plot_3d_scatter_data,
    plot_3d_scatter_data_interactive,
    plot_3d_scatter_data_interactive_grouped,
    plot_heatmap_ma_scores,
    plot_scatter_data,
)


if __name__ == "__main__":

    args = argparse.ArgumentParser()
    args.add_argument("--filepath", type=str, help="Path to the events log file")
    args = args.parse_args()

    df = load_event_dataframe(args.filepath)
    df_rewards = preprocess_data_for_plotting(df, 'rewards')
    df_completion_times = preprocess_data_for_plotting(df, 'completion_times')
    df_moving_averaged_scores = preprocess_moving_avg_scores(df, 'moving_averaged_scores')

    plot_scatter_data(df_rewards, 'rewards', 'Rewards Over Time by UID')
    plot_scatter_data(df_completion_times, 'completion_times', 'Completion Times Over Time by UID')

    plot_3d_scatter_data(df_rewards, 'rewards', '3D Scatter of Rewards Over Time by UID')
    plot_3d_scatter_data(df_completion_times, 'completion_times', '3D Scatter of Completion Times Over Time by UID')

    plot_3d_scatter_data_interactive(df_rewards, 'rewards', 'Interactive 3D Scatter of Rewards Over Time by UID')
    plot_3d_scatter_data_interactive(df_completion_times, 'completion_times', 'Interactive 3D Scatter of Completion Times Over Time by UID')

    plot_heatmap_ma_scores(df_moving_averaged_scores)

    plot_3d_scatter_data_interactive_grouped(df_rewards, 'rewards', 'Rewards over time by Task')
    plot_3d_scatter_data_interactive_grouped(df_completion_times, 'completion_times', 'Completion times over time by Task')
