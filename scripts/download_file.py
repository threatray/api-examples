import argparse

from threatray_client import ConfigError, get_client


def download_file(file_hash: str, dest_path: str) -> None:
    client = get_client()
    with client.stream_get(f"/v1/files/{file_hash}/data?zipped") as r:
        if r.status_code != 200:
            print(f"File does not exist, status code: {r.status_code}")
            return
        with open(dest_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=64 * 1024):
                if chunk:
                    f.write(chunk)
    print(f"Downloaded file to: {dest_path}")
    print('The ZIP is password-protected. Password: "infected".')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download a sample by hash (as a password-protected ZIP).")
    parser.add_argument("--hash", required=True, type=str, help="Hash (MD5, SHA1, SHA256) of the file to download.")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output path for the ZIP (default: <hash>.zip).")

    args = parser.parse_args()

    dest = args.output or f"{args.hash}.zip"
    try:
        download_file(args.hash, dest)
    except ConfigError as e:
        raise SystemExit(f"error: {e}")
