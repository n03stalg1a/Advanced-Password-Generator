import secrets
import string
import math
import os
import re
from colorama import Fore, Style, init
import pyfiglet
from datetime import datetime

# Initialize colorama for better cross-platform compatibility
init(autoreset=True)

# List of common passwords to avoid (GitHub link for reference)
COMMON_PASSWORDS_GITHUB_LINK = "https://github.com/digininja/Common-Passwords"

# Function to generate a secure password
def generate_advanced_password(length=16, min_upper=2, min_lower=2, min_digits=2, min_special=2, max_consecutive=2):
    """
    Generates a cryptographically secure password while ensuring high complexity, with protections against common patterns.
    
    :param length: Length of the password (default: 16)
    :param min_upper: Minimum number of uppercase letters (default: 2)
    :param min_lower: Minimum number of lowercase letters (default: 2)
    :param min_digits: Minimum number of digits (default: 2)
    :param min_special: Minimum number of special characters (default: 2)
    :param max_consecutive: Maximum number of consecutive identical characters (default: 2)
    :return: A cryptographically secure password
    """
    
    # Define character sets
    upper_chars = string.ascii_uppercase
    lower_chars = string.ascii_lowercase
    digits = string.digits
    special_chars = string.punctuation
    all_chars = upper_chars + lower_chars + digits + special_chars

    # Ensure minimum requirements
    password_chars = (
        secrets.choice(upper_chars) for _ in range(min_upper)
    ) + (
        secrets.choice(lower_chars) for _ in range(min_lower)
    ) + (
        secrets.choice(digits) for _ in range(min_digits)
    ) + (
        secrets.choice(special_chars) for _ in range(min_special)
    )
    
    # Fill up the rest with a random mix
    remaining_length = length - (min_upper + min_lower + min_digits + min_special)
    password_chars += (secrets.choice(all_chars) for _ in range(remaining_length))
    
    # Shuffle to avoid predictable patterns
    password_list = list(password_chars)
    secrets.SystemRandom().shuffle(password_list)
    password = ''.join(password_list)

    # Apply additional security checks
    if has_common_patterns(password):
        raise ValueError("Generated password contains common patterns or weak sequences.")
    if has_consecutive_characters(password, max_consecutive):
        raise ValueError("Generated password contains too many consecutive identical characters.")
    
    return password

def calculate_entropy(password):
    """
    Calculates the entropy of the password. Entropy is a measure of password strength.
    
    :param password: The password to analyze
    :return: The entropy of the password
    """
    charset_size = len(set(password))
    return math.log2(charset_size ** len(password))

def has_common_patterns(password):
    """
    Checks if the password contains any common password patterns or easily guessable words.
    
    :param password: The password to check
    :return: True if it contains common patterns, False otherwise
    """
    return password.lower() in COMMON_PASSWORDS or re.search(r'(.)\1{2,}', password)

def has_consecutive_characters(password, max_consecutive):
    """
    Checks if the password contains more than the allowed number of consecutive identical characters.
    
    :param password: The password to check
    :param max_consecutive: The allowed maximum consecutive identical characters
    :return: True if there are too many consecutive identical characters
    """
    for i in range(len(password) - max_consecutive):
        if len(set(password[i:i + max_consecutive])) == 1:
            return True
    return False

# Function to display the title in ASCII art
def display_title():
    ascii_art = pyfiglet.figlet_format("NSA Password Gen", font="slant")
    print(Fore.RED + ascii_art)
    print(Fore.CYAN + "Welcome to the NSA-level Secure Password Generator!" + Style.BRIGHT)
    print(Fore.YELLOW + "Generated passwords are cryptographically strong and highly secure." + Style.RESET_ALL)

# Function to display common password information
def display_common_password_warning():
    print(Fore.RED + "\nWarning: The following are common passwords and should be avoided at all costs:")
    print(Fore.CYAN + f"  You can find an up-to-date list of common passwords to avoid at: {COMMON_PASSWORDS_GITHUB_LINK}")
    print(Fore.YELLOW + "Ensure your passwords do not fall into these categories.")

# Function to create a directory with the current date and save the password
def save_password_to_file(password):
    # Get the current date for folder name
    current_date = datetime.now().strftime("%Y-%m-%d")
    folder_name = f"Passwords_{current_date}"
    
    # Create folder if it doesn't exist
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    
    # Save password to a file inside the new folder
    password_file = os.path.join(folder_name, f"password_{current_date}.txt")
    with open(password_file, 'w') as f:
        f.write(password)
    print(Fore.GREEN + f"\nPassword saved to {password_file}")

# Display the title and warning
display_title()
display_common_password_warning()

# Generate and display the password
password = generate_advanced_password(length=24, min_upper=3, min_lower=3, min_digits=3, min_special=3)
print(Fore.GREEN + f"Generated Password: {password}")

# Save the password to a folder with the current date
save_password_to_file(password)

# Calculate and display password entropy
entropy = calculate_entropy(password)
print(Fore.MAGENTA + f"Password Entropy: {entropy:.2f} bits")

# Entropy advice
if entropy < 80:
    print(Fore.RED + "Warning: Password strength is below recommended levels. Consider using a longer password or more character variety.")
else:
    print(Fore.GREEN + "Password strength is high. Your password is secure.")

print(Style.RESET_ALL)
