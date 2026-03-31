# shodancli

`shodancli` is an extensible Python command-line client for the Shodan API.
Currently, it only supports the `explore` command for discovering exposed systems across individual IPv4 addresses and ranges.

## Installation

`shodancli` can be installed using a Python package manager of your choice.
Below are some popular options — we recommend using either `pipx` or `uv`.

### `pipx`

```bash
pipx install "git+https://github.com/ret2src/shodancli.git"
```

### `uv`

```bash
uv tool install "git+https://github.com/ret2src/shodancli.git"
```

### `pip`

```bash
python3 -m pip install "git+https://github.com/ret2src/shodancli.git"
```

### Local Development Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

## Usage

Set your Shodan API key:

```bash
export SHODAN_API_KEY=your_key_here
```

Show top-level help:

```bash
shodancli --help
```

Show command help:

```bash
shodancli explore --help
```

### "Explore" Command

`shodancli explore` currently supports:

- Individual IPv4 addresses such as `192.0.2.10`
- CIDR ranges such as `192.0.2.0/24`
- Dash ranges such as `198.51.100.10-198.51.100.50`

The output includes:

- Discovered IPs (and hostnames if available)
- Discovered Ports (per range and overall)
- System counts (per range and overall)

Explore IPv4 ranges with inline inputs:

```bash
shodancli explore --ranges "192.0.2.10, 192.0.2.0/24, 198.51.100.10-198.51.100.50"
```

Explore IPv4 ranges from a line-separated input file:

```bash
shodancli explore --file ranges.txt
```

Explore IPv4 ranges from STDIN:

```bash
cat ranges.txt | shodancli explore
```
