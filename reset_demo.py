"""Optional reset of disposable fictional site data. Requires --yes."""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'app'))
from database import DB_PATH, initialize


def main():
    parser=argparse.ArgumentParser(description='Reset fictional VulnScope Portal database')
    parser.add_argument('--yes',action='store_true', help='Confirm deletion of fictional portal data')
    args=parser.parse_args()
    if not args.yes:
        print('Will reset all comments and demo profile changes. Run with --yes to confirm.')
        return
    if DB_PATH.exists():
        DB_PATH.unlink()
    initialize()
    print('Demo employees, tickets and accounts restored. Restart Flask to reload the app.')


if __name__=='__main__':
    main()
