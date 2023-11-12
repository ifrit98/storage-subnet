import numpy as np

def generate_file_size_with_lognormal(mu=np.log(10 * 1024**2), sigma=1.5):
    """
    Generate a single file size using a lognormal distribution.
    Default parameters are set to model a typical file size distribution,
    but can be overridden for custom distributions.

    :param mu: Mean of the log values, default is set based on medium file size (10 MB).
    :param sigma: Standard deviation of the log values, default is set to 1.5.
    :return: File size in bytes.
    """

    # Generate a file size using the lognormal distribution
    file_size = np.random.lognormal(mean=mu, sigma=sigma)

    # Scale the file size to a realistic range (e.g., bytes)
    scaled_file_size = int(file_size)

    return scaled_file_size

# Example usage
sample_file_size = generate_file_size_with_lognormal()  # using default parameters
custom_sample_file_size = generate_file_size_with_lognormal(mu=np.log(5 * 1024**2), sigma=2)  # custom parameters

sample_file_size, custom_sample_file_size
