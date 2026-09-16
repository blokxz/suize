"""Modelos de resultados de escaneo: :class:`Host` y :class:`Port`."""

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Port:
    """Un puerto detectado por Nmap en un host."""

    number: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""

    @property
    def is_open(self) -> bool:
        """``True`` para ``open`` y también para ``open|filtered``.

        En UDP, Nmap casi nunca puede distinguir un puerto abierto de uno
        filtrado: si el servicio no contesta a la sonda, responde
        ``open|filtered``. Tratarlo como cerrado dejaría vacía la tabla de casi
        cualquier escaneo UDP y diría "sin puertos abiertos" sobre un equipo que
        sí los tiene.
        """
        return self.state.startswith("open")

    @property
    def version_label(self) -> str:
        """Producto, versión e información extra en una sola cadena legible."""
        label = " ".join(part for part in (self.product, self.version) if part)
        if self.extra_info:
            label = f"{label} ({self.extra_info})" if label else self.extra_info
        return label


@dataclass(slots=True)
class Host:
    """Un host del escaneo con sus puertos."""

    address: str
    address_type: str = "ipv4"
    hostnames: list[str] = field(default_factory=list)
    status: str = "unknown"
    mac: str = ""
    ports: list[Port] = field(default_factory=list)

    @property
    def hostname(self) -> str:
        """Primer hostname conocido, o cadena vacía."""
        return self.hostnames[0] if self.hostnames else ""

    @property
    def is_up(self) -> bool:
        return self.status == "up"

    @property
    def open_ports(self) -> list[Port]:
        return [port for port in self.ports if port.is_open]
