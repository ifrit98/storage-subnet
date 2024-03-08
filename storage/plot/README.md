# FileTAO Validator Quality of Life and Introspection Improvements

This update introduces several Quality of Life (QoL) and introspection improvements for validators within the FileTAO network. These enhancements are focused on providing more in-depth analytics and visualization of validator performance, making it easier for validators to understand their operations and optimize accordingly.

## Features

- **Events Logging to JSON**: Validators can now log event data in a structured JSON format, enabling easier data analysis and processing.
- **Scatter Plots**: Visualize rewards and completion times using scatter plots to quickly identify trends and outliers in validator performance.
- **Interactive 3D Maps**: Explore the data in three dimensions with interactive 3D maps for a more immersive data analysis experience.

## Installation

Before you can utilize these new plotting functionalities, ensure that the necessary dependencies are installed. Run the following command to install the required plotting libraries:

```bash
python -m pip install -r requirements.plot.txt
```

## Usage

The plotting functionality is encapsulated within a Python script that processes event logs to generate visualizations. Here's a quick overview of how to use it:

1. **Load Event Data**: Event logs are loaded into a Pandas DataFrame for easy manipulation and analysis.

2. **Preprocess Data**: The data is preprocessed to expand list columns and prepare it for plotting.

3. **Generate Plots**:
   - Scatter plots and 3D scatter plots for rewards and completion times, offering insights into validator performance across different tasks and time.
   - Heatmaps of moving averaged scores to visualize the performance stability of validators over time.

4. **Interactive 3D Maps**: Interactive plots are generated using Plotly, allowing users to explore the data dynamically.

## Visualizations

- **Interactive Map of Rewards by Task**: A visual representation of the rewards obtained by validators, categorized by tasks.
  
- **Interactive Map of Completion Time by Task**: A visualization of the time it takes validators to complete tasks, providing insights into efficiency.

- **Heatmap of Moving Averaged Scores**: Displays the moving averaged scores of validators, showcasing their performance stability over time.

## How to Run

To generate the plots, simply execute the provided Python script with an optional argument to specify the path to your event log file:

```bash
python scripts/plot_events.py --filepath /path/to/your/events_log.json
```

If no filepath is provided, the script will attempt to load the default event log file located at `~/.bittensor/miners/default/validator/netuid21/core_storage_validator/events.json`.

## Examples of Generated Visualizations

- **Interactive Map of Rewards by Task**: ![Interactive Map of Rewards by Task](https://github.com/ifrit98/storage-subnet/assets/31426574/ed3cd70f-f963-4fdb-8b06-5dfc1b78c7ce)

- **Interactive Map of Completion Time by Task**: ![Interactive Map of Completion Time by Task](https://github.com/ifrit98/storage-subnet/assets/31426574/b1e68a61-9df8-411a-8653-3993e07e616e)

- **Heatmap of Moving Averaged Scores**: ![Heatmap of Moving Averaged Scores](https://github.com/ifrit98/storage-subnet/assets/31426574/e0b3dd55-1347-4cd6-afbe-3bac0af1c436)

## Conclusion

These new features enhance the visibility and understanding of validators' performance within the FileTAO network. By leveraging detailed logging and advanced visualizations, validators can better see how their rewards are distributed across the network.