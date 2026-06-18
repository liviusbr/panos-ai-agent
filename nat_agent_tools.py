"""
Pydantic tool schemas for NAT rule CRUD via Claude tool calling.
Imported by webapp.py for the /api/nat/interpret endpoint.
"""
from typing import Optional, List, Literal
from pydantic import BaseModel, Field


class CreateNatRule(BaseModel):
    """Create a new NAT rule on the firewall."""
    name: str = Field(description="Unique rule name, hyphen-separated e.g. 'snat-trust-to-untrust'")
    source_zones: List[str] = Field(description="Source zones e.g. ['trust']")
    destination_zone: str = Field(description="Single destination zone e.g. 'untrust'")
    source_addresses: List[str] = Field(default=["any"])
    destination_addresses: List[str] = Field(default=["any"])
    service: str = Field(default="any")
    disabled: bool = Field(default=False)

    # Source NAT
    sat_type: Literal["dynamic-ip-and-port", "dynamic-ip", "static-ip", "none"] = Field(
        default="dynamic-ip-and-port",
        description="Source address translation type. 'dynamic-ip-and-port' = PAT/masquerade (most common). "
                    "'static-ip' = 1:1 NAT. 'none' = no source translation."
    )
    sat_interface: Optional[str] = Field(
        default=None,
        description="Egress interface for dynamic-ip-and-port e.g. 'ethernet1/1'. "
                    "Only used when sat_type is dynamic-ip-and-port."
    )
    sat_translated_addresses: Optional[List[str]] = Field(
        default=None,
        description="Translated address pool for dynamic-ip. Only used when sat_type is dynamic-ip."
    )
    sat_static_translated_address: Optional[str] = Field(
        default=None,
        description="Translated address for static-ip NAT."
    )
    sat_static_bi_directional: bool = Field(
        default=False,
        description="Enable bi-directional static NAT."
    )

    # Destination NAT
    dat_address: Optional[str] = Field(
        default=None,
        description="Translated destination address for DNAT e.g. '192.168.1.100'. "
                    "Omit if no destination translation needed."
    )
    dat_port: Optional[int] = Field(
        default=None,
        description="Translated destination port for DNAT e.g. 8080. Omit if no port translation."
    )


class UpdateNatRule(BaseModel):
    """Modify fields on an existing NAT rule."""
    name: str = Field(description="Name of the existing NAT rule to modify")
    source_zones: Optional[List[str]] = None
    destination_zone: Optional[str] = None
    source_addresses: Optional[List[str]] = None
    destination_addresses: Optional[List[str]] = None
    service: Optional[str] = None
    disabled: Optional[bool] = None
    sat_type: Optional[Literal["dynamic-ip-and-port", "dynamic-ip", "static-ip", "none"]] = None
    sat_interface: Optional[str] = None
    sat_translated_addresses: Optional[List[str]] = None
    sat_static_translated_address: Optional[str] = None
    sat_static_bi_directional: Optional[bool] = None
    dat_address: Optional[str] = None
    dat_port: Optional[int] = None


class DeleteNatRule(BaseModel):
    """Delete an existing agent-managed NAT rule by name."""
    name: str = Field(description="Name of the NAT rule to delete")


NAT_TOOLS = [CreateNatRule, UpdateNatRule, DeleteNatRule]
