"""Create a login for the hosted IOC Checker.

Run:  python make_user.py manager

It makes a random password, shows it once, and prints the entry to add to the IOC_USERS setting on your host.
Only the scrambled hash goes in IOC_USERS; the password itself is never stored. Nothing is written to disk.
"""
import secrets
import sys

import auth


def main():
    """Make one login for the name given on the command line and print the password and the IOC_USERS entry."""
    if len(sys.argv) != 2 or not auth.USERNAME_PATTERN.match(sys.argv[1]):
        raise SystemExit("usage: python make_user.py <name>   (a-z, 0-9, _ and - only, up to 32 characters)")

    name = sys.argv[1]
    password = secrets.token_urlsafe(12)
    print(f"Login for {name}")
    print(f"  Password (shown once, send it separately from the link): {password}")
    print("  Add this entry to IOC_USERS, joining several users with commas:")
    print(f"  {name}={auth.hash_password(password)}")


if __name__ == "__main__":
    main()
