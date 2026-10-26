from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    locations: tuple[str, ...] = ()
    dev: bool = False

    @property
    def key(self):
        return f"{self.ecosystem}:{self.name}@{self.version}"

    def to_dict(self):
        return asdict(self)


@dataclass
class ParsedManifest:
    packages: list[Dependency] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    format: str = ""


@dataclass
class QueryResult:
    ids: list[str] = field(default_factory=list)
    error: str = ""
