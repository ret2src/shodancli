from __future__ import annotations

import ipaddress
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Iterable

import requests
from requests import Response
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm
from rich.table import Table


STDOUT = Console(stderr=False)
STDERR = Console(stderr=True)
SHODAN_URL = "https://api.shodan.io/shodan/host/search"
SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
PAGE_SIZE = 100
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
CONFIRMATION_THRESHOLD = 4096


@dataclass
class SystemRecord:
    ip: str
    hostnames: set[str] = field(default_factory=set)
    ports: set[int] = field(default_factory=set)

    def merge_match(self, match: dict) -> None:
        for hostname in match.get("hostnames") or []:
            if hostname:
                self.hostnames.add(hostname)
        port = match.get("port")
        if isinstance(port, int):
            self.ports.add(port)


@dataclass
class TargetSpec:
    kind: str
    original: str
    sanitized: str
    size: int
    query_cidrs: list[str] = field(default_factory=list)
    query_ips: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    systems: dict[str, SystemRecord] = field(default_factory=dict)
    query_total: int = 0


class InputError(Exception):
    pass


def warn(message: str) -> None:
    STDERR.print(f"[yellow]Warning:[/] {message}")


def error(message: str) -> None:
    STDERR.print(f"[red]Error:[/] {message}")


def sanitize_text_blob(raw: str) -> str:
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    normalized = re.sub(r"\s*-\s*", "-", normalized)
    normalized = re.sub(r"\s*/\s*", "/", normalized)
    normalized = normalized.replace(",", "\n")
    return normalized


def tokenize_text(raw: str) -> list[str]:
    normalized = sanitize_text_blob(raw)
    return [token for token in normalized.split() if token and token.strip(",:;")]


def strip_outer_noise(token: str) -> tuple[str, list[str]]:
    warnings: list[str] = []
    sanitized = token.strip()
    trimmed = sanitized.strip(",:;")
    if trimmed != sanitized:
        warnings.append(f"sanitized token '{token}' -> '{trimmed}'")
    return trimmed, warnings


def parse_ipv4(value: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise InputError(str(exc)) from exc


def build_target_spec(token: str) -> TargetSpec:
    sanitized, warnings = strip_outer_noise(token)
    if not sanitized:
        raise InputError(f"empty token derived from '{token}'")

    if IPV4_RE.fullmatch(sanitized):
        ip = str(parse_ipv4(sanitized))
        if ip != sanitized:
            warnings.append(f"normalized IP '{sanitized}' -> '{ip}'")
        return TargetSpec(
            kind="ip",
            original=token,
            sanitized=ip,
            size=1,
            query_ips=[ip],
            warnings=warnings,
        )

    if "/" in sanitized:
        try:
            network = ipaddress.IPv4Network(sanitized, strict=False)
        except ValueError as exc:
            raise InputError(f"invalid CIDR range '{sanitized}': {exc}") from exc
        if network.num_addresses == 1:
            ip = str(network.network_address)
            warnings.append(f"normalized single-host CIDR '{sanitized}' -> '{ip}'")
            return TargetSpec(
                kind="ip",
                original=token,
                sanitized=ip,
                size=1,
                query_ips=[ip],
                warnings=warnings,
            )
        canonical = str(network)
        if canonical != sanitized:
            warnings.append(f"normalized CIDR '{sanitized}' -> '{canonical}'")
        return TargetSpec(
            kind="cidr",
            original=token,
            sanitized=canonical,
            size=network.num_addresses,
            query_cidrs=[canonical],
            warnings=warnings,
        )

    if "-" in sanitized:
        parts = sanitized.split("-")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise InputError(f"invalid dash range '{sanitized}'")
        start = parse_ipv4(parts[0])
        end = parse_ipv4(parts[1])
        if start == end:
            ip = str(start)
            warnings.append(f"normalized single-host range '{sanitized}' -> '{ip}'")
            return TargetSpec(
                kind="ip",
                original=token,
                sanitized=ip,
                size=1,
                query_ips=[ip],
                warnings=warnings,
            )
        if int(start) > int(end):
            raise InputError(f"range start is greater than end in '{sanitized}'")
        cidrs = [str(net) for net in ipaddress.summarize_address_range(start, end)]
        canonical = f"{start}-{end}"
        if canonical != sanitized:
            warnings.append(f"normalized range '{sanitized}' -> '{canonical}'")
        return TargetSpec(
            kind="dash",
            original=token,
            sanitized=canonical,
            size=(int(end) - int(start) + 1),
            query_cidrs=cidrs,
            warnings=warnings,
        )

    raise InputError(f"unsupported target format: '{sanitized}'")


def collect_input_tokens(args) -> list[str]:
    tokens: list[str] = []

    for inline_value in args.ranges:
        inline_tokens = tokenize_text(inline_value)
        if not inline_tokens:
            warn("received an empty inline input")
        tokens.extend(inline_tokens)

    for file_path in args.file:
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                file_tokens = tokenize_text(handle.read())
        except OSError as exc:
            raise InputError(f"failed to read input file '{file_path}': {exc}") from exc
        if not file_tokens:
            warn(f"input file '{file_path}' did not contain any targets")
        tokens.extend(file_tokens)

    if not sys.stdin.isatty():
        stdin_tokens = tokenize_text(sys.stdin.read())
        if not stdin_tokens:
            warn("STDIN was provided but did not contain any targets")
        tokens.extend(stdin_tokens)

    if not tokens:
        raise InputError("no input targets provided via --ranges, --file, or STDIN")

    return tokens


def build_target_specs(tokens: Iterable[str]) -> list[TargetSpec]:
    specs: list[TargetSpec] = []
    seen: set[str] = set()
    for token in tokens:
        try:
            spec = build_target_spec(token)
        except InputError as exc:
            warn(str(exc))
            continue
        for message in spec.warnings:
            warn(message)
        if spec.sanitized in seen:
            warn(f"duplicate input ignored: '{spec.sanitized}'")
            continue
        seen.add(spec.sanitized)
        specs.append(spec)
    if not specs:
        raise InputError("no valid inputs remained after validation")
    return specs


def confirm_broad_specs(specs: list[TargetSpec]) -> list[TargetSpec]:
    approved: list[TargetSpec] = []
    interactive = sys.stdin.isatty() and sys.stderr.isatty()

    for spec in specs:
        if spec.kind == "ip" or spec.size <= CONFIRMATION_THRESHOLD:
            approved.append(spec)
            continue

        prompt = (
            f"Input '{spec.sanitized}' covers {spec.size} addresses, which exceeds "
            f"the confirmation threshold of {CONFIRMATION_THRESHOLD}. Continue?"
        )
        if interactive:
            if Confirm.ask(prompt, console=STDERR, default=False):
                approved.append(spec)
            else:
                warn(f"skipping broad input '{spec.sanitized}'")
        else:
            warn(
                f"skipping broad input '{spec.sanitized}' because confirmation is required "
                "and no interactive terminal is available"
            )

    if not approved:
        raise InputError("no approved inputs remained after broad-range confirmation")
    return approved


def shodan_request(api_key: str, query: str, page: int, timeout: float) -> Response:
    return requests.get(
        SHODAN_URL,
        params={"key": api_key, "query": query, "page": page},
        timeout=timeout,
    )


def shodan_host_request(api_key: str, ip: str, timeout: float) -> Response:
    return requests.get(
        SHODAN_HOST_URL.format(ip=ip),
        params={"key": api_key},
        timeout=timeout,
    )


def search_cidr(api_key: str, cidr: str, timeout: float) -> list[dict]:
    page = 1
    matches: list[dict] = []
    query = f'net:"{cidr}"'

    while True:
        response = shodan_request(api_key, query, page, timeout)
        if response.status_code == 401:
            raise RuntimeError("Shodan API authentication failed")
        if response.status_code == 403:
            raise RuntimeError("Shodan API access forbidden for this account or query")
        if response.status_code == 429:
            raise RuntimeError("Shodan API rate limit exceeded")
        if not response.ok:
            raise RuntimeError(
                f"Shodan API request failed for {cidr} with status {response.status_code}: {response.text[:200]}"
            )

        payload = response.json()
        page_matches = payload.get("matches") or []
        matches.extend(page_matches)
        total = int(payload.get("total") or 0)

        if len(matches) >= total or not page_matches or len(page_matches) < PAGE_SIZE:
            return matches
        page += 1


def lookup_ip(api_key: str, ip: str, timeout: float) -> dict | None:
    response = shodan_host_request(api_key, ip, timeout)
    if response.status_code == 404:
        return None
    if response.status_code == 401:
        raise RuntimeError("Shodan API authentication failed")
    if response.status_code == 403:
        raise RuntimeError("Shodan API access forbidden for this account or query")
    if response.status_code == 429:
        raise RuntimeError("Shodan API rate limit exceeded")
    if not response.ok:
        raise RuntimeError(
            f"Shodan host lookup failed for {ip} with status {response.status_code}: {response.text[:200]}"
        )
    payload = response.json()
    return {
        "ip_str": payload.get("ip_str") or ip,
        "hostnames": payload.get("hostnames") or [],
        "ports": payload.get("ports") or [],
    }


def populate_systems(api_key: str, specs: list[TargetSpec], timeout: float) -> bool:
    had_errors = False
    total_steps = sum(len(spec.query_cidrs) + len(spec.query_ips) for spec in specs)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=STDERR,
        transient=True,
    ) as progress:
        task_id = progress.add_task("Querying Shodan", total=total_steps or 1)
        for spec in specs:
            for ip in spec.query_ips:
                progress.update(task_id, description=f"Looking up {spec.sanitized}")
                try:
                    match = lookup_ip(api_key, ip, timeout)
                except requests.RequestException as exc:
                    had_errors = True
                    error(f"request failed for {spec.sanitized}: {exc}")
                    progress.advance(task_id)
                    continue
                except RuntimeError as exc:
                    had_errors = True
                    error(f"{spec.sanitized}: {exc}")
                    progress.advance(task_id)
                    continue

                if match is not None:
                    spec.query_total += 1
                    record = spec.systems.setdefault(ip, SystemRecord(ip=ip))
                    record.hostnames.update(hostname for hostname in match.get("hostnames", []) if hostname)
                    for port in match.get("ports", []):
                        if isinstance(port, int):
                            record.ports.add(port)
                progress.advance(task_id)

            for cidr in spec.query_cidrs:
                progress.update(task_id, description=f"Searching {spec.sanitized}")
                try:
                    matches = search_cidr(api_key, cidr, timeout)
                except requests.RequestException as exc:
                    had_errors = True
                    error(f"request failed for {spec.sanitized} via {cidr}: {exc}")
                    progress.advance(task_id)
                    continue
                except RuntimeError as exc:
                    had_errors = True
                    error(f"{spec.sanitized} via {cidr}: {exc}")
                    progress.advance(task_id)
                    continue

                spec.query_total += len(matches)
                for match in matches:
                    ip = match.get("ip_str")
                    if not ip:
                        warn(f"Shodan returned a match without ip_str for input {spec.sanitized}")
                        continue
                    record = spec.systems.setdefault(ip, SystemRecord(ip=ip))
                    record.merge_match(match)
                progress.advance(task_id)
    return had_errors


def render_output(specs: list[TargetSpec]) -> None:
    global_systems: dict[str, SystemRecord] = {}

    STDOUT.print(
        Panel.fit(
            "[bold cyan]Shodan Explore Report[/]\n"
            "[dim]Overall total is globally deduplicated by IP across all inputs.[/]",
            border_style="cyan",
        )
    )

    for spec in specs:
        for ip, record in spec.systems.items():
            merged = global_systems.setdefault(ip, SystemRecord(ip=ip))
            merged.hostnames.update(record.hostnames)
            merged.ports.update(record.ports)

        table = Table(
            title=f"Input: {spec.sanitized}",
            title_style="bold green",
            header_style="bold magenta",
            border_style="green",
            show_lines=False,
        )
        table.add_column("IP", style="cyan", no_wrap=True)
        table.add_column("Hostname", style="white")
        table.add_column("Ports", style="yellow")

        for record in sorted(spec.systems.values(), key=lambda item: tuple(int(part) for part in item.ip.split("."))):
            hostname = ", ".join(sorted(record.hostnames)) if record.hostnames else "-"
            ports = ", ".join(str(port) for port in sorted(record.ports)) if record.ports else "-"
            table.add_row(record.ip, hostname, ports)

        if not spec.systems:
            label = "IP" if spec.kind == "ip" else "Input"
            STDOUT.print(Panel.fit(f"[bold green]{label}: {spec.sanitized}[/]\nNo systems found.", border_style="green"))
        else:
            STDOUT.print(table)

        spec_ports = sorted({port for system in spec.systems.values() for port in system.ports})
        ports_display = ", ".join(str(port) for port in spec_ports) if spec_ports else "-"
        STDOUT.print(
            f"[bold green]Input total:[/] {len(spec.systems)} unique systems "
            f"[dim](from {spec.query_total} raw Shodan matches across "
            f"{len(spec.query_cidrs) + len(spec.query_ips)} Shodan request target(s))[/]"
        )
        STDOUT.print(f"[bold green]Discovered ports:[/] {ports_display}")
        STDOUT.print()

    summary = Table(title="Summary", title_style="bold cyan", header_style="bold blue", border_style="cyan")
    summary.add_column("Input", style="green")
    summary.add_column("Type", style="magenta")
    summary.add_column("Unique Systems", justify="right", style="yellow")
    summary.add_column("Discovered Ports", style="cyan")
    for spec in specs:
        spec_ports = sorted({port for system in spec.systems.values() for port in system.ports})
        ports_display = ", ".join(str(port) for port in spec_ports) if spec_ports else "-"
        summary.add_row(spec.sanitized, spec.kind, str(len(spec.systems)), ports_display)
    overall_ports = sorted({port for system in global_systems.values() for port in system.ports})
    overall_ports_display = ", ".join(str(port) for port in overall_ports) if overall_ports else "-"
    summary.add_row("[bold]Overall[/]", "[bold]-[/]", f"[bold]{len(global_systems)}[/]", f"[bold]{overall_ports_display}[/]")
    STDOUT.print(summary)


def run(args) -> int:
    api_key = args.api_key or os.environ.get("SHODAN_API_KEY")
    if not api_key:
        error("missing Shodan API key. Use --api-key or set SHODAN_API_KEY.")
        return 2

    try:
        tokens = collect_input_tokens(args)
        specs = confirm_broad_specs(build_target_specs(tokens))
    except InputError as exc:
        error(str(exc))
        return 2

    had_runtime_errors = populate_systems(api_key, specs, args.timeout)
    render_output(specs)
    return 1 if had_runtime_errors else 0
