import calendar
import datetime
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlunparse

from . import enterprise_types
from . import enterprise_constants
from .. import crypto, errors, utils
from ..authentication import keeper_auth
from ..proto import APIRequest_pb2, BI_pb2, breachwatch_pb2, enterprise_pb2
from .private_data import _decrypt_encrypted_data

_KEPM_ADDON = 'keeper_endpoint_privilege_manager'
_REMOTE_BROWSER_ISOLATION_ADDON = 'remote_browser_isolation'
_CONNECTION_MANAGER_ADDON = 'connection_manager'
_KEPM_VALID_SEATS = frozenset({1, 25, 50, 100, 500, 1000, 5000, 10000})

# API uses signed 32-bit INT_MAX for unlimited seat counts.
_INT32_MAX = (1 << 31) - 1
_SEATS_UNLIMITED_THRESHOLD = _INT32_MAX - 1

_CMD_ENTERPRISE_REGISTRATION_BY_MSP = 'enterprise_registration_by_msp'
_CMD_ENTERPRISE_UPDATE_BY_MSP = 'enterprise_update_by_msp'
_CMD_ENTERPRISE_REMOVE_BY_MSP = 'enterprise_remove_by_msp'
_CMD_ENTERPRISE_ALLOCATE_IDS = 'enterprise_allocate_ids'
_CMD_QUERY_ENTERPRISE = 'query_enterprise'
_CMD_ROLE_ADD = 'role_add'
_CMD_ROLE_ENFORCEMENT_ADD = 'role_enforcement_add'
_CMD_ROLE_ENFORCEMENT_UPDATE = 'role_enforcement_update'
_CMD_ROLE_ENFORCEMENT_REMOVE = 'role_enforcement_remove'
_CMD_GET_MC_LICENSE_ADJUSTMENT_LOG = 'get_mc_license_adjustment_log'
_REST_LOGIN_TO_MC = 'authentication/login_to_mc'
_REST_NODE_TO_MANAGED_COMPANY = 'enterprise/node_to_managed_company'
_REST_USER_DATA_KEY_BY_NODE = 'enterprise/get_enterprise_user_data_key_by_node'
_REST_MC_PUBLIC_KEY = 'enterprise/get_enterprise_public_key'
_BI_CONSOLE_ADDONS_MAPPING = 'mapping/addons'
_BI_CONSOLE_MC_PRICING = 'subscription/mc_pricing'
_BI_API_PREFIX = '/bi_api/v2/enterprise_console/'

_JSON_KEY_DISPLAYNAME = 'displayname'
_DISPLAYNAME_KEEPER_ADMIN = 'Keeper Administrator'
_DISPLAYNAME_ROOT = 'root'

_MSG_NO_MC_RESTRICTIONS = 'MSP has no restrictions'
_MSG_NO_MANAGED_COMPANIES = 'No Managed Companies'
_DEFAULT_CONVERT_PLAN = 'business'
_KEY_TYPE_NO_KEY = 'no_key'
_ENCRYPTED_BY_DATA_KEY = 'encrypted_by_data_key'
_USER_DATA_KEY_TYPE_ID_ECC = 4
_UNKNOWN_USER_LABEL = '?'
_LEGACY_DATE_RANGES = (
    'today',
    'yesterday',
    'last_7_days',
    'last_30_days',
    'month_to_date',
    'last_month',
    'year_to_date',
    'last_year',
)


@dataclass(frozen=True)
class MspInfoReport:
    """Tabular MSP info."""
    headers: Tuple[str, ...]
    rows: Tuple[Tuple[Any, ...], ...]
    row_numbers: bool = False
    message: Optional[str] = None


@dataclass(frozen=True)
class MspBillingReport:
    headers: Tuple[str, ...]
    rows: Tuple[Tuple[Any, ...], ...]
    title: str


@dataclass(frozen=True)
class MspLegacyReport:
    headers: Tuple[str, ...]
    rows: Tuple[Tuple[Any, ...], ...]
    title: Optional[str] = None


def login_to_managed_company(loader: enterprise_types.IEnterpriseLoader, mc_enterprise_id: int) -> Tuple[keeper_auth.KeeperAuth, bytes]:
    auth = loader.keeper_auth
    tree_key = loader.enterprise_data.enterprise_info.tree_key
    rq = enterprise_pb2.LoginToMcRequest()
    rq.mcEnterpriseId = mc_enterprise_id
    rs = auth.execute_auth_rest(_REST_LOGIN_TO_MC, rq, response_type=enterprise_pb2.LoginToMcResponse)
    assert rs is not None
    auth_context = keeper_auth.AuthContext()
    auth_context.username = auth.auth_context.username
    auth_context.account_uid = auth.auth_context.account_uid
    auth_context.data_key = auth.auth_context.data_key
    auth_context.device_token = auth.auth_context.device_token
    auth_context.device_private_key = auth.auth_context.device_private_key
    auth_context.session_token = rs.encryptedSessionToken
    encrypted_tree_key = utils.base64_url_decode(rs.encryptedTreeKey)
    mc_tree_key = crypto.decrypt_aes_v2(encrypted_tree_key, tree_key)
    mc_auth = keeper_auth.KeeperAuth(auth.keeper_endpoint, auth_context)
    mc_auth.post_login()

    return mc_auth, mc_tree_key


def msp_down(loader: enterprise_types.IEnterpriseLoader, *, reset: bool = False) -> Set[int]:
    """Download current MSP enterprise data from the Keeper cloud.

    :param loader: Active enterprise loader (MSP context).
    :param reset: When True, clears continuation state and forces a full resync.
    :return: Entity type ids touched during this load.
    """
    return loader.load(reset=reset)


def switch_to_msp(loader: enterprise_types.IEnterpriseLoader) -> Set[int]:
    """Refresh MSP enterprise data when switching back from MC context."""
    return msp_down(loader, reset=False)


def decrypt_managed_company_tree_key(encrypted_tree_key_b64: str, msp_tree_key: bytes) -> Optional[bytes]:
    """Decrypt a managed company tree key blob using the MSP enterprise tree key (AES-GCM v2)."""
    if not encrypted_tree_key_b64:
        return None
    try:
        return crypto.decrypt_aes_v2(utils.base64_url_decode(encrypted_tree_key_b64), msp_tree_key)
    except Exception:
        return None


def _bi_enterprise_console_url(auth: keeper_auth.KeeperAuth, endpoint: str) -> str:
    host = auth.keeper_endpoint.server
    path = _BI_API_PREFIX + endpoint.lstrip('/')
    return urlunparse(('https', host, path, '', '', ''))


def _node_path(enterprise_data: enterprise_types.IEnterpriseData, node_id: int, *, omit_root: bool) -> str:
    nodes: List[str] = []
    n_id = node_id
    while isinstance(n_id, int) and n_id > 0:
        node = enterprise_data.nodes.get_entity(n_id)
        if node:
            n_id = node.parent_id or 0
            if not omit_root or n_id > 0:
                node_name = node.name
                if not node_name and node.node_id == enterprise_data.root_node.node_id:
                    node_name = enterprise_data.enterprise_info.enterprise_name
                nodes.append(node_name)
        else:
            break
    nodes.reverse()
    return '\\'.join(nodes)


class _MspBillingCurrency(str, Enum):
    """API ``currency`` codes from billing/price payloads."""

    USD = '$'
    EUR = '\u20ac'
    GBP = '\u00a3'
    JPY = '\u00a5'


class _MspPriceUnit(str, Enum):
    """API ``unit`` codes from billing/price payloads."""

    USER_MONTH = 'user/month'
    MONTH = 'month'
    USER_CONSUMED_MONTH = '50k API calls/month'


def _billing_currency_display(currency: Any) -> Optional[str]:
    if currency is None or currency == '':
        return None
    key = str(currency)
    member = _MspBillingCurrency.__members__.get(key)
    return member.value if member is not None else key


def _price_unit_display(unit: Any) -> Optional[str]:
    if unit is None or unit == '':
        return None
    key = str(unit)
    member = _MspPriceUnit.__members__.get(key)
    return member.value if member is not None else key


def _price_text_short(price_info: Dict[str, Any]) -> str:
    price = ''
    amount = price_info.get('amount')
    if amount is not None:
        display_currency = _billing_currency_display(price_info.get('currency'))
        if display_currency:
            price += display_currency
        price += str(amount)
    return price


def _price_text(price_info: Dict[str, Any]) -> str:
    price = _price_text_short(price_info)
    if price:
        display_unit = _price_unit_display(price_info.get('unit'))
        if display_unit:
            price += '/' + display_unit
    return price


def _fetch_msp_addon_id_to_name(auth: keeper_auth.KeeperAuth) -> Dict[int, str]:
    url = _bi_enterprise_console_url(auth, _BI_CONSOLE_ADDONS_MAPPING)
    rq = BI_pb2.MappingAddonsRequest()
    rs = auth.execute_auth_rest(url, rq, response_type=BI_pb2.MappingAddonsResponse)
    if not rs:
        raise errors.KeeperError("No response received from mapping addons API")
    return {x.id: x.name for x in rs.addons}


def _fetch_mc_pricing(auth: keeper_auth.KeeperAuth) -> Dict[str, Dict[str, Dict[str, Any]]]:
    plan_map = {x[0]: x[1] for x in enterprise_constants.MSP_PLANS}
    file_map = {x[0]: x[1] for x in enterprise_constants.MSP_FILE_PLANS}
    addon_map = _fetch_msp_addon_id_to_name(auth)

    pricing: Dict[str, Dict[str, Dict[str, Any]]] = {
        'mc_base_plans': {},
        'mc_addons': {},
        'mc_file_plans': {},
    }

    url = _bi_enterprise_console_url(auth, _BI_CONSOLE_MC_PRICING)
    rq = BI_pb2.SubscriptionMcPricingRequest()
    rs = auth.execute_auth_rest(url, rq, response_type=BI_pb2.SubscriptionMcPricingResponse)
    if not rs:
        raise errors.KeeperError("No response received from subscription mc pricing API")

    for bp in rs.basePlans:
        if bp.id in plan_map:
            code = plan_map[bp.id]
            pricing['mc_base_plans'][code] = {
                'amount': bp.cost.amount,
                'unit': BI_pb2.Cost.AmountPer.Name(bp.cost.amountPer),
                'currency': BI_pb2.Currency.Name(bp.cost.currency),
            }
    for ap in rs.addons:
        if ap.id in addon_map:
            name = addon_map[ap.id]
            pricing['mc_addons'][name] = {
                'amount': ap.cost.amount,
                'unit': BI_pb2.Cost.AmountPer.Name(ap.cost.amountPer),
                'currency': BI_pb2.Currency.Name(ap.cost.currency),
                'amount_consumed': ap.amountConsumed,
            }
    for fp in rs.filePlans:
        if fp.id in file_map:
            code = file_map[fp.id]
            pricing['mc_file_plans'][code] = {
                'amount': fp.cost.amount,
                'unit': BI_pb2.Cost.AmountPer.Name(fp.cost.amountPer),
                'currency': BI_pb2.Currency.Name(fp.cost.currency),
            }
    return pricing


def _find_managed_company(
    enterprise_data: enterprise_types.IEnterpriseData,
    name_or_id: Union[int, str],
) -> Optional[enterprise_types.ManagedCompany]:
    if isinstance(name_or_id, int):
        return enterprise_data.managed_companies.get_entity(name_or_id)
    key = name_or_id.lower()
    for mc in enterprise_data.managed_companies.get_all_entities():
        if mc.mc_enterprise_name.lower() == key:
            return mc
    return None


def _parse_managed_company_filter(mc: Optional[str]) -> Optional[Union[int, str]]:
    if mc is None or (isinstance(mc, str) and not mc.strip()):
        return None
    s = mc.strip()
    if s.isdigit():
        return int(s)
    return s


def _first_msp_permits(enterprise_data: enterprise_types.IEnterpriseData) -> Optional[enterprise_types.MspPermits]:
    for lic in enterprise_data.licenses.get_all_entities():
        if lic.msp_permits is not None:
            return lic.msp_permits
    return None


def _lookup_msp_product_plan(plan: str) -> Optional[Tuple[Any, ...]]:
    plan_name = plan.strip().lower()
    return next((x for x in enterprise_constants.MSP_PLANS if x[1].lower() == plan_name), None)


def _lookup_msp_file_plan_row(file_plan: str) -> Optional[Tuple[Any, ...]]:
    fp_name = file_plan.strip().lower()
    return next(
        (
            x
            for x in enterprise_constants.MSP_FILE_PLANS
            if fp_name in (str(y).lower() for y in x if isinstance(y, str))
        ),
        None,
    )


def _msp_info_restriction_report(enterprise_data: enterprise_types.IEnterpriseData) -> MspInfoReport:
    permits = _first_msp_permits(enterprise_data)
    if not permits:
        return MspInfoReport(headers=(), rows=(), message=_MSG_NO_MC_RESTRICTIONS)
    all_products = {x[1].lower(): x[2] for x in enterprise_constants.MSP_PLANS}
    all_addons = {x[0].lower(): x[3] for x in enterprise_constants.MSP_ADDONS}
    all_file_plans = {x[1].lower(): x[2] for x in enterprise_constants.MSP_FILE_PLANS}
    max_file_plan = permits.max_file_plan_type
    allowed_products = permits.allowed_mc_products or []
    allowed_addons = permits.allowed_add_ons or []
    table = [
        ('Allow Unlimited Licenses', permits.allow_unlimited_licenses),
        ('Allowed Products', [x + f' ({all_products.get(x.lower(), "")})' for x in allowed_products]),
        ('Allowed Add-Ons', [x + f' ({all_addons.get(x.lower(), "")})' for x in allowed_addons]),
        ('Max File Storage plan', all_file_plans.get(max_file_plan.lower(), max_file_plan)),
    ]
    return MspInfoReport(headers=('permit_name', 'value'), rows=tuple((a, b) for a, b in table))


def _msp_info_pricing_report(auth: keeper_auth.KeeperAuth) -> MspInfoReport:
    pricing_data = _fetch_mc_pricing(auth)
    header = ('category', 'name', 'code', 'price')
    rows: List[Tuple[Any, ...]] = []
    base_plans = pricing_data.get('mc_base_plans') or {}
    for plan in enterprise_constants.MSP_PLANS:
        code = plan[1]
        if code in base_plans:
            rows.append(('Product', plan[2], code, _price_text(base_plans[code])))
    addons = pricing_data.get('mc_addons') or {}
    for addon in enterprise_constants.MSP_ADDONS:
        code = addon[0]
        if code in addons:
            rows.append(('Addon', addon[1], code, _price_text(addons[code])))
    fplans = pricing_data.get('mc_file_plans') or {}
    for fp in enterprise_constants.MSP_FILE_PLANS:
        plan_code = fp[1]
        if plan_code in fplans:
            rows.append(('File Plan', fp[2], plan_code, _price_text(fplans[plan_code])))
    return MspInfoReport(headers=header, rows=tuple(rows))


def _resolve_managed_companies_for_info(
    enterprise_data: enterprise_types.IEnterpriseData,
    managed_company: Optional[str],
) -> List[enterprise_types.ManagedCompany]:
    mcs = list(enterprise_data.managed_companies.get_all_entities())
    flt = _parse_managed_company_filter(managed_company)
    if flt is None:
        return mcs
    mc_one = _find_managed_company(enterprise_data, flt)
    if mc_one is None:
        raise errors.KeeperError(f'Managed Company "{managed_company}" not found')
    return [mc_one]


def _addon_display_strings_for_mc_row(
    mc: enterprise_types.ManagedCompany,
    *,
    verbose: bool,
) -> List[str]:
    addon_list: List[str] = []
    if not mc.add_ons:
        return addon_list
    for addon_obj in mc.add_ons:
        addon_name = addon_obj.name
        if not verbose:
            addon_list.append(addon_name)
            continue
        seats = addon_obj.seats
        if seats and seats > 0:
            addon_def = next((x for x in enterprise_constants.MSP_ADDONS if x[0] == addon_name), None)
            if addon_def and addon_def[2]:
                display_seats = -1 if seats == _INT32_MAX else seats
                addon_list.append(f'{addon_name}:{display_seats}')
            else:
                addon_list.append(addon_name)
        else:
            addon_list.append(addon_name)
    return addon_list


def _msp_info_managed_companies_report(
    enterprise_data: enterprise_types.IEnterpriseData,
    mcs: List[enterprise_types.ManagedCompany],
    *,
    verbose: bool,
) -> MspInfoReport:
    sort_dict = {x[0]: i for i, x in enumerate(enterprise_constants.MSP_ADDONS)}
    plan_map = {x[1]: x[2] for x in enterprise_constants.MSP_PLANS}
    file_plan_map = {x[1]: x[2] for x in enterprise_constants.MSP_FILE_PLANS}
    header = ['company_id', 'company_name', 'node', 'plan', 'storage', 'addons', 'allocated', 'active']
    if verbose:
        header.insert(3, 'node_name')

    table_rows: List[Tuple[Any, ...]] = []
    for mc in mcs:
        node_id = mc.msp_node_id
        if verbose:
            node_path = str(node_id)
            node_name = _node_path(enterprise_data, node_id, omit_root=False)
        else:
            node_path = _node_path(enterprise_data, node_id, omit_root=False)
            node_name = None

        file_plan_label = file_plan_map.get(mc.file_plan_type, mc.file_plan_type)
        addon_list = _addon_display_strings_for_mc_row(mc, verbose=verbose)
        addon_list.sort(key=lambda x: sort_dict.get(x.split(':')[0], -1))
        addons: Any = addon_list if verbose else len(addon_list)

        plan = mc.product_id
        if not verbose:
            plan = plan_map.get(plan, plan)

        seats = mc.number_of_seats
        if seats > _SEATS_UNLIMITED_THRESHOLD:
            seats = -1

        users = mc.number_of_users or 0
        if verbose:
            table_rows.append((
                mc.mc_enterprise_id, mc.mc_enterprise_name, node_path, node_name, plan, file_plan_label, addons, seats, users,
            ))
        else:
            table_rows.append((
                mc.mc_enterprise_id, mc.mc_enterprise_name, node_path, plan, file_plan_label, addons, seats, users,
            ))

    table_rows.sort(key=lambda x: str(x[1]).lower())
    return MspInfoReport(headers=tuple(header), rows=tuple(table_rows), row_numbers=True)


def msp_info(
    loader: enterprise_types.IEnterpriseLoader,
    *,
    restriction: bool = False,
    pricing: bool = False,
    managed_company: Optional[str] = None,
    verbose: bool = False,
) -> MspInfoReport:
    """Build MSP information reports."""
    enterprise_data = loader.enterprise_data
    auth = loader.keeper_auth

    if restriction:
        return _msp_info_restriction_report(enterprise_data)
    if pricing:
        return _msp_info_pricing_report(auth)

    mcs = _resolve_managed_companies_for_info(enterprise_data, managed_company)
    if len(mcs) == 0:
        return MspInfoReport(headers=(), rows=(), message=_MSG_NO_MANAGED_COMPANIES)
    return _msp_info_managed_companies_report(enterprise_data, mcs, verbose=verbose)


def _billing_is_plan_id(msp_id: int) -> bool:
    return 0 < msp_id < 100


def _billing_is_storage_plan_id(msp_id: int) -> bool:
    return 100 < msp_id < 10000


def _billing_is_addon_id(msp_id: int) -> bool:
    return msp_id > 10000


def _billing_count_id(msp_id: int) -> int:
    if _billing_is_plan_id(msp_id):
        return msp_id
    if _billing_is_storage_plan_id(msp_id):
        return msp_id // 100
    if _billing_is_addon_id(msp_id):
        return msp_id // 10000
    return 0


def _merge_billing_units(unit_dicts: List[Optional[Dict[int, Any]]]) -> Dict[int, Tuple[int, int]]:
    merged: Dict[int, Tuple[int, int]] = {}
    for units in unit_dicts:
        if not isinstance(units, dict):
            continue
        for unit, count in units.items():
            if not isinstance(unit, int):
                continue
            if isinstance(count, int):
                qty, days = count, 1
            elif isinstance(count, tuple) and len(count) >= 2:
                qty, days = int(count[0]), int(count[1])
            else:
                continue
            q0, d0 = merged.get(unit, (0, 0))
            merged[unit] = (q0 + qty, d0 + days)
    return merged


def _fetch_daily_billing_snapshots(
    auth: keeper_auth.KeeperAuth,
    *,
    year: int,
    month: int,
) -> Tuple[Dict[Tuple[int, int], Dict[int, int]], Dict[int, str]]:
    url = _bi_enterprise_console_url(auth, 'reporting/daily_snapshot')
    rq = BI_pb2.ReportingDailySnapshotRequest()
    rq.year = year
    rq.month = month
    rs = auth.execute_auth_rest(url, rq, response_type=BI_pb2.ReportingDailySnapshotResponse)
    if not rs:
        raise errors.KeeperError('No response received from daily snapshot API')

    company_lookup: Dict[int, str] = {x.id: x.name for x in rs.mcEnterprises}
    snapshots: Dict[Tuple[int, int], Dict[int, int]] = {}
    for record in rs.records:
        units: Dict[int, int] = {}
        if record.maxLicenseCount > 0:
            if record.maxBasePlanId > 0:
                units[record.maxBasePlanId] = record.maxLicenseCount
            if record.maxFilePlanTypeId > 0:
                units[record.maxFilePlanTypeId * 100] = record.maxLicenseCount
            for addon in record.addons:
                if addon.maxAddonId > 0:
                    units[addon.maxAddonId * 10000] = addon.units
        ds = datetime.datetime.fromtimestamp(record.date / 1000.0, tz=datetime.timezone.utc)
        snapshots[(record.mcEnterpriseId, ds.date().toordinal())] = units
    return snapshots, company_lookup


def _billing_bounding_snapshots(
    period_snapshots: Dict[Tuple[int, int], Dict[int, int]],
    mc_id: Optional[int] = None,
) -> Tuple[Optional[Dict[int, Any]], Optional[Dict[int, Any]]]:
    by_mc_dates: Dict[int, List[int]] = {}
    for this_mc, date_no in period_snapshots.keys():
        if mc_id is not None and this_mc != mc_id:
            continue
        by_mc_dates.setdefault(this_mc, []).append(date_no)
    if not by_mc_dates:
        return None, None

    if mc_id is not None:
        dates = by_mc_dates.get(mc_id) or []
        if not dates:
            return None, None
        start_key = (mc_id, min(dates))
        end_key = (mc_id, max(dates))
        return period_snapshots.get(start_key), period_snapshots.get(end_key)

    start_list: List[Dict[int, int]] = []
    end_list: List[Dict[int, int]] = []
    for company_id, dates in by_mc_dates.items():
        start_data = period_snapshots.get((company_id, min(dates)))
        end_data = period_snapshots.get((company_id, max(dates)))
        if start_data:
            start_list.append(start_data)
        if end_data:
            end_list.append(end_data)
    return _merge_billing_units(start_list), _merge_billing_units(end_list)


def _billing_reported_days(period_snapshots: Dict[Tuple[int, int], Dict[int, int]]) -> int:
    dates = [x[1] for x in period_snapshots.keys()]
    return max(dates) - min(dates) + 1 if dates else 30


def _billing_max_product_count(
    period_snapshots: Dict[Tuple[int, int], Dict[int, int]],
    product: int,
    mc_id: Optional[int] = None,
) -> int:
    daily_totals: Dict[int, int] = {}
    for (company_id, date_no), counts in period_snapshots.items():
        if mc_id is not None and company_id != mc_id:
            continue
        daily_totals[date_no] = daily_totals.get(date_no, 0) + int(counts.get(product) or 0)
    return max(daily_totals.values()) if daily_totals else 0


def msp_billing_report(
    loader: enterprise_types.IEnterpriseLoader,
    *,
    month: Optional[str] = None,
    show_date: bool = False,
    show_company: bool = False,
) -> MspBillingReport:
    auth = loader.keeper_auth

    if month:
        year_part, sep, month_part = month.partition('-')
        if sep != '-':
            raise errors.KeeperError(f'Given month "{month}" is not valid. Expected YYYY-MM')
        try:
            year = int(year_part)
            month_no = int(month_part)
        except Exception:
            raise errors.KeeperError(f'Given month "{month}" is not valid. Expected YYYY-MM') from None
    else:
        now = datetime.datetime.now()
        year = now.year
        month_no = now.month - 1
        if month_no < 1:
            month_no = 12
            year -= 1
    if month_no < 1 or month_no > 12:
        raise errors.KeeperError(f'Given month "{month}" is not valid. Expected YYYY-MM')

    daily_counts, company_lookup = _fetch_daily_billing_snapshots(auth, year=year, month=month_no)
    merged_counts: Dict[Tuple[int, int], Dict[int, Tuple[int, int]]] = {}
    for (mc_id, date_no), units in daily_counts.items():
        key = (mc_id if show_company else 0, date_no if show_date else 0)
        merged_counts[key] = _merge_billing_units([merged_counts.get(key), units])

    headers: List[str] = []
    if show_date:
        headers.append('date')
    if show_company:
        headers.extend(['company', 'company_id'])
    headers.extend(['product', 'licenses', 'rate'])
    if not show_date:
        headers.extend(['avg_per_day', 'initial_licenses', 'final_licenses', 'max_licenses'])

    plan_lookup = {x[0]: x for x in enterprise_constants.MSP_PLANS}
    storage_lookup = {x[0]: x for x in enterprise_constants.MSP_FILE_PLANS}
    addon_lookup: Dict[int, Tuple[Any, ...]] = {}
    addons = {x[0]: x for x in enterprise_constants.MSP_ADDONS}
    for addon_id, addon_name in _fetch_msp_addon_id_to_name(auth).items():
        if addon_name in addons:
            addon_lookup[addon_id] = addons[addon_name]
    pricing = _fetch_mc_pricing(auth)

    rows: List[Tuple[Any, ...]] = []
    for (mc_id, date_no), counts in sorted(merged_counts.items(), key=lambda x: (x[0][1], x[0][0])):
        day_str = str(datetime.date.fromordinal(date_no)) if show_date else ''
        company_name = company_lookup.get(mc_id, '') if show_company else ''
        start_snapshot, end_snapshot = (None, None) if show_date else _billing_bounding_snapshots(
            daily_counts, mc_id=mc_id if show_company else None)
        for product in sorted(counts.keys()):
            count_id = _billing_count_id(product)
            if show_company:
                count, days = counts[product]
            else:
                count = counts[product][0]
                days = _billing_reported_days(daily_counts)

            product_name = str(product)
            rate_text = ''
            if _billing_is_plan_id(product):
                plan = plan_lookup.get(count_id)
                if plan:
                    product_name = plan[2]
                    rate = pricing.get('mc_base_plans', {}).get(plan[1])
                    if rate:
                        rate_text = _price_text_short(rate)
            elif _billing_is_storage_plan_id(product):
                storage_plan = storage_lookup.get(count_id)
                if storage_plan:
                    product_name = storage_plan[2]
                    rate = pricing.get('mc_file_plans', {}).get(storage_plan[1])
                    if rate:
                        rate_text = _price_text_short(rate)
            elif _billing_is_addon_id(product):
                addon = addon_lookup.get(count_id)
                if addon:
                    product_name = addon[1]
                    rate = pricing.get('mc_addons', {}).get(addon[0])
                    if rate:
                        rate_text = _price_text_short(rate)

            row: List[Any] = []
            if show_date:
                row.append(day_str)
            if show_company:
                row.extend([company_name, mc_id])
            row.extend([product_name, count, rate_text])

            if not show_date:
                avg_per_day = round(count / days, 2) if days else 0
                start_raw = 0 if start_snapshot is None else (start_snapshot.get(product) or 0)
                end_raw = 0 if end_snapshot is None else (end_snapshot.get(product) or 0)
                start_count = start_raw[0] if isinstance(start_raw, tuple) else start_raw
                end_count = end_raw[0] if isinstance(end_raw, tuple) else end_raw
                max_count = _billing_max_product_count(
                    daily_counts, product, mc_id if show_company else None)
                row.extend([avg_per_day, start_count, end_count, max_count])
            rows.append(tuple(row))

    title = f'Consumption Billing Statement: {calendar.month_name[month_no]} {year}'
    return MspBillingReport(headers=tuple(headers), rows=tuple(rows), title=title)


def _legacy_date_range_to_dates(range_name: str) -> Tuple[datetime.datetime, datetime.datetime]:
    if range_name not in _LEGACY_DATE_RANGES:
        raise errors.KeeperError(
            f'Given range {range_name} is not supported. Supported ranges: {", ".join(_LEGACY_DATE_RANGES)}')

    current_time = datetime.datetime.now()
    today_start_dt = current_time.replace(hour=0, minute=0, second=0, microsecond=0)

    today_end_dt = current_time.replace(hour=23, minute=59, second=59, microsecond=0)

    def last_day_of_month(dt: datetime.datetime) -> datetime.datetime:
        year = dt.year
        month = int(dt.strftime('%m')) % 12 + 1
        ldom = calendar.monthrange(year, month)[1]
        return dt.replace(hour=23, minute=59, second=59, microsecond=0, day=ldom)

    if range_name == 'today':
        return today_start_dt, today_end_dt
    if range_name == 'yesterday':
        return today_start_dt - datetime.timedelta(days=1), today_end_dt - datetime.timedelta(days=1)
    if range_name == 'last_7_days':
        return today_start_dt - datetime.timedelta(days=7), today_end_dt
    if range_name == 'last_30_days':
        return today_start_dt - datetime.timedelta(days=30), today_end_dt
    if range_name == 'month_to_date':
        return today_start_dt.replace(day=1), today_end_dt
    if range_name == 'last_month':
        last_month_num = current_time.month - 1 if current_time.month > 1 else 12
        last_month_dt = current_time.replace(month=last_month_num)
        return current_time.replace(month=last_month_num, day=1, hour=0, minute=0, second=0, microsecond=0), \
            last_day_of_month(last_month_dt)
    if range_name == 'year_to_date':
        return today_start_dt.replace(day=1, month=1), today_end_dt
    prev_year = today_start_dt.year - 1
    return today_start_dt.replace(year=prev_year, day=1, month=1), \
        today_start_dt.replace(year=prev_year, day=31, month=12, hour=23, minute=59, second=59, microsecond=0)


def _parse_legacy_date_str(value: str, *, is_end: bool) -> datetime.datetime:
    v = (value or '').strip()
    if not v:
        raise errors.KeeperError('Date value is empty')
    try:
        return datetime.datetime.fromtimestamp(int(v))
    except Exception:
        pass
    suffix = '23:59:59' if is_end else '00:00:00'
    try:
        return datetime.datetime.strptime(f'{v} {suffix}', '%Y-%m-%d %H:%M:%S')
    except Exception:
        raise errors.KeeperError(f'Date "{value}" is invalid. Expected YYYY-MM-DD or unix timestamp') from None


def msp_legacy_report(
    loader: enterprise_types.IEnterpriseLoader,
    *,
    range_name: str = 'last_30_days',
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
) -> MspLegacyReport:
    """Generate the legacy MSP license adjustment report."""
    auth = loader.keeper_auth

    if from_date and to_date:
        from_dt = _parse_legacy_date_str(from_date, is_end=False)
        to_dt = _parse_legacy_date_str(to_date, is_end=True)
    else:
        from_dt, to_dt = _legacy_date_range_to_dates(range_name)

    rq = {
        'command': _CMD_GET_MC_LICENSE_ADJUSTMENT_LOG,
        'from': int(from_dt.timestamp() * 1000),
        'to': int(to_dt.timestamp() * 1000),
    }
    rs = auth.execute_auth_command(rq)

    headers = (
        'id', 'time', 'company_id', 'company_name', 'status',
        'number_of_allocations', 'plan', 'transaction_notes', 'price_estimate',
    )
    rows: List[Tuple[Any, ...]] = []
    for log in rs.get('log', []) if isinstance(rs, dict) else []:
        if not isinstance(log, dict):
            continue
        rows.append((
            log.get('id'),
            log.get('date'),
            log.get('enterprise_id'),
            log.get('enterprise_name'),
            log.get('status'),
            log.get('new_number_of_seats'),
            log.get('new_product_type'),
            log.get('note'),
            log.get('price'),
        ))
    return MspLegacyReport(headers=headers, rows=tuple(rows), title=None)


def _new_mc_encrypted_registration_fields(mc_tree_key: bytes, msp_tree_key: bytes) -> Dict[str, Any]:
    role_json = json.dumps({_JSON_KEY_DISPLAYNAME: _DISPLAYNAME_KEEPER_ADMIN}).encode()
    root_json = json.dumps({_JSON_KEY_DISPLAYNAME: _DISPLAYNAME_ROOT}).encode()
    return {
        'encrypted_tree_key': utils.base64_url_encode(crypto.encrypt_aes_v2(mc_tree_key, msp_tree_key)),
        'role_data': utils.base64_url_encode(crypto.encrypt_aes_v1(role_json, mc_tree_key)),
        'root_node': utils.base64_url_encode(crypto.encrypt_aes_v1(root_json, mc_tree_key)),
    }


def _registration_seat_cap(seats: Optional[int], permits: Optional[enterprise_types.MspPermits]) -> int:
    seat_val = 0 if seats is None else int(seats)
    if seat_val < 0:
        if permits and not permits.allow_unlimited_licenses:
            raise errors.KeeperError('Managed Company unlimited licences are not allowed')
        return _INT32_MAX
    return seat_val


def _assert_mc_product_plan_allowed(
    plan_label: str,
    plan_name_lower: str,
    permits: Optional[enterprise_types.MspPermits],
) -> None:
    if not permits or permits.allowed_mc_products is None:
        return
    allowed_products = permits.allowed_mc_products
    if len(allowed_products) == 0 or not any(x.lower() == plan_name_lower for x in allowed_products):
        raise errors.KeeperError(f'Managed Company plan "{plan_label}" is not allowed')


def _assert_file_plan_allowed_by_permits(
    fp_row: Tuple[Any, ...],
    permits: Optional[enterprise_types.MspPermits],
) -> None:
    if not permits or not permits.max_file_plan_type:
        return
    allowed_fp = next(
        (x for x in enterprise_constants.MSP_FILE_PLANS if permits.max_file_plan_type.lower() == x[1].lower()),
        None,
    )
    if allowed_fp and allowed_fp[0] < fp_row[0]:
        raise errors.KeeperError(f'Managed Company file storage "{fp_row[2]}" is not allowed')


def _merge_optional_file_plan_into_registration_rq(
    rq: Dict[str, Any],
    file_plan: Optional[str],
    product_plan: Tuple[Any, ...],
    permits: Optional[enterprise_types.MspPermits],
) -> None:
    if not file_plan:
        return
    fp_row = _lookup_msp_file_plan_row(file_plan)
    if not fp_row:
        raise errors.KeeperError(f'File plan "{file_plan}" is not found')
    if product_plan[3] < fp_row[0]:
        rq['file_plan_type'] = fp_row[1]
    _assert_file_plan_allowed_by_permits(fp_row, permits)


def _addon_seats_from_spec_line(
    addon_name: str,
    *,
    has_seat_token: bool,
    seat_part: str,
    spec: Tuple[Any, ...],
    seat_label_for_errors: str,
) -> int:
    if not (has_seat_token and spec[2]):
        return 0
    sp = seat_part.strip()
    if addon_name == _KEPM_ADDON and sp == '-1':
        return _INT32_MAX
    try:
        addon_seats = int(sp)
    except ValueError:
        raise errors.KeeperError(
            f'Addon "{addon_name}". Number of seats "{seat_label_for_errors}" is not integer') from None
    if addon_name == _KEPM_ADDON:
        if addon_seats not in _KEPM_VALID_SEATS and addon_seats != _INT32_MAX:
            valid_values = ', '.join(str(x) for x in sorted(_KEPM_VALID_SEATS)) + ', -1 (for unlimited)'
            raise errors.KeeperError(
                f'Addon "{addon_name}". Invalid seat value "{seat_label_for_errors}". Valid values are: {valid_values}')
    return addon_seats


def _registration_addon_lines_to_rq(
    rq: Dict[str, Any],
    addon_lines: List[str],
    permits: Optional[enterprise_types.MspPermits],
) -> Dict[str, int]:
    addon_data: Dict[str, int] = {}
    rq['add_ons'] = []
    for line in addon_lines:
        addon_name, sep, seat_part = line.partition(':')
        addon_name = addon_name.lower().strip()
        spec = next((x for x in enterprise_constants.MSP_ADDONS if x[0] == addon_name), None)
        if spec is None:
            raise errors.KeeperError(f'Addon "{addon_name}" is not found')
        if permits and permits.allowed_add_ons is not None and len(permits.allowed_add_ons) > 0:
            if addon_name not in (x.lower() for x in permits.allowed_add_ons):
                raise errors.KeeperError(f'Managed Company add-on "{addon_name}" is not allowed')
        addon_seats = _addon_seats_from_spec_line(
            addon_name,
            has_seat_token=(sep == ':' and bool(spec[2])),
            seat_part=seat_part,
            spec=spec,
            seat_label_for_errors=seat_part,
        )
        rqa: Dict[str, Any] = {'add_on': spec[0]}
        if addon_seats > 0:
            rqa['seats'] = addon_seats
            addon_data[addon_name] = addon_seats
        else:
            addon_data[addon_name] = 0
        rq['add_ons'].append(rqa)
    return addon_data


def _assert_remote_browser_requires_connection_manager_seats(addon_name_to_seats: Dict[str, int]) -> None:
    if _REMOTE_BROWSER_ISOLATION_ADDON not in addon_name_to_seats:
        return
    if _CONNECTION_MANAGER_ADDON not in addon_name_to_seats:
        raise errors.KeeperError(
            f'Addon "{_REMOTE_BROWSER_ISOLATION_ADDON}" requires "{_CONNECTION_MANAGER_ADDON}" to be selected')
    if addon_name_to_seats.get(_CONNECTION_MANAGER_ADDON, 0) == 0:
        raise errors.KeeperError(
            f'Addon "{_REMOTE_BROWSER_ISOLATION_ADDON}" requires "{_CONNECTION_MANAGER_ADDON}" '
            f'to have seats specified (e.g. {_CONNECTION_MANAGER_ADDON}:N)')


def _assert_remote_browser_requires_connection_manager_update(addons: Dict[str, Dict[str, Any]]) -> None:
    addon_keys = {k.lower() for k in addons}
    if _REMOTE_BROWSER_ISOLATION_ADDON not in addon_keys:
        return
    if _CONNECTION_MANAGER_ADDON not in addon_keys:
        raise errors.KeeperError(
            f'Addon "{_REMOTE_BROWSER_ISOLATION_ADDON}" requires "{_CONNECTION_MANAGER_ADDON}" to be selected')
    cm_addon = addons.get(_CONNECTION_MANAGER_ADDON)
    if cm_addon:
        cm_seats = int(cm_addon.get('seats', 0) or 0)
        if cm_seats == 0:
            raise errors.KeeperError(
                f'Addon "{_REMOTE_BROWSER_ISOLATION_ADDON}" requires "{_CONNECTION_MANAGER_ADDON}" '
                f'to have seats specified (e.g. {_CONNECTION_MANAGER_ADDON}:N)')


def msp_add_managed_company(
    loader: enterprise_types.IEnterpriseLoader,
    *,
    enterprise_name: str,
    plan: str,
    node_id: int,
    seats: Optional[int] = None,
    file_plan: Optional[str] = None,
    addons: Optional[List[str]] = None,
) -> int:
    """Register a new managed company.

    :param loader: MSP enterprise loader.
    :param enterprise_name: Display name for the new managed company.
    :param plan: Product plan code (e.g. ``business``, ``enterprise``); must match :data:`enterprise_constants.MSP_PLANS`.
    :param node_id: Enterprise node id under which the MC is created.
    :param seats: Seat cap; use ``-1`` or ``None`` with unlimited permits for unlimited (signed 32-bit max, server-side).
    :param file_plan: Optional storage plan code (e.g. ``STORAGE_100GB``).
    :param addons: Optional ``ADDON`` or ``ADDON:SEATS`` strings.
    :return: New managed company enterprise id.
    """
    enterprise_data = loader.enterprise_data
    auth = loader.keeper_auth
    msp_tree_key = enterprise_data.enterprise_info.tree_key

    for mc in enterprise_data.managed_companies.get_all_entities():
        if mc.mc_enterprise_name.lower() == enterprise_name.strip().lower():
            raise errors.KeeperError(f"Managed company '{enterprise_name}' already exists")

    permits = _first_msp_permits(enterprise_data)
    plan_name = plan.strip().lower()
    product_plan = _lookup_msp_product_plan(plan)
    if not product_plan:
        raise errors.KeeperError(f'Managed Company plan "{plan}" is not found')
    _assert_mc_product_plan_allowed(plan, plan_name, permits)

    seat_val = _registration_seat_cap(seats, permits)
    mc_tree_key = utils.generate_aes_key()
    rq: Dict[str, Any] = {
        'command': _CMD_ENTERPRISE_REGISTRATION_BY_MSP,
        'node_id': node_id,
        'product_id': product_plan[1],
        'seats': seat_val,
        'enterprise_name': enterprise_name.strip(),
        **_new_mc_encrypted_registration_fields(mc_tree_key, msp_tree_key),
    }

    _merge_optional_file_plan_into_registration_rq(rq, file_plan, product_plan, permits)

    if addons:
        addon_data = _registration_addon_lines_to_rq(rq, addons, permits)
        _assert_remote_browser_requires_connection_manager_seats(addon_data)

    rs = auth.execute_auth_command(rq)
    company_id = int(rs.get('enterprise_id', -1))
    if company_id < 0:
        raise errors.KeeperError('Managed company registration did not return an enterprise id')
    msp_down(loader, reset=False)
    return company_id


def _selectable_addons_from_managed_company(
    current: enterprise_types.ManagedCompany,
) -> Dict[str, Dict[str, Any]]:
    addons: Dict[str, Dict[str, Any]] = {}
    if not current.add_ons:
        return addons
    for ao in current.add_ons:
        if not ao.enabled or ao.included_in_product:
            continue
        entry: Dict[str, Any] = {'add_on': ao.name}
        if ao.seats and ao.seats > 0:
            entry['seats'] = ao.seats
        addons[ao.name.lower()] = entry
    return addons


def _apply_update_rq_plan(
    rq: Dict[str, Any],
    plan: str,
    permits: Optional[enterprise_types.MspPermits],
) -> None:
    plan_name = plan.strip().lower()
    product_plan = _lookup_msp_product_plan(plan)
    if not product_plan:
        raise errors.KeeperError(f'Managed Company plan "{plan}" is not found')
    _assert_mc_product_plan_allowed(plan, plan_name, permits)
    rq['product_id'] = product_plan[1]


def _apply_update_rq_seats(
    rq: Dict[str, Any],
    seats: int,
    permits: Optional[enterprise_types.MspPermits],
) -> None:
    if seats < 0:
        if permits and not permits.allow_unlimited_licenses:
            raise errors.KeeperError('Managed Company unlimited licences are not allowed')
        rq['seats'] = _INT32_MAX
    else:
        rq['seats'] = seats


def _apply_file_plan_fields_to_mc_update_rq(
    rq: Dict[str, Any],
    file_plan: Optional[str],
    current: enterprise_types.ManagedCompany,
    permits: Optional[enterprise_types.MspPermits],
) -> None:
    if file_plan is not None:
        fp_row = _lookup_msp_file_plan_row(file_plan)
        if not fp_row:
            raise errors.KeeperError(f'File plan "{file_plan}" is not found')
        _assert_file_plan_allowed_by_permits(fp_row, permits)
        product_id = str(rq['product_id']).lower()
        product_plan = next((x for x in enterprise_constants.MSP_PLANS if product_id == x[1].lower()), None)
        if product_plan and product_plan[3] < fp_row[0]:
            rq['file_plan_type'] = fp_row[1]
        return
    existing_file_plan = current.file_plan_type
    if not existing_file_plan:
        return
    product_id = str(rq['product_id']).lower()
    product_plan = next((x for x in enterprise_constants.MSP_PLANS if product_id == x[1].lower()), None)
    if not product_plan:
        return
    fp_existing = next((x for x in enterprise_constants.MSP_FILE_PLANS if x[1] == existing_file_plan), None)
    if fp_existing and fp_existing[0] != product_plan[3]:
        rq['file_plan_type'] = existing_file_plan


def _apply_update_addon_mutations(
    addons: Dict[str, Dict[str, Any]],
    *,
    add_lines: List[str],
    remove_lines: List[str],
    permits: Optional[enterprise_types.MspPermits],
) -> None:
    for aon in add_lines:
        addon_name, sep, seat_str = aon.partition(':')
        addon_name = addon_name.lower().strip()
        spec = next((x for x in enterprise_constants.MSP_ADDONS if x[0] == addon_name), None)
        if spec is None:
            raise errors.KeeperError(f'Addon "{addon_name}" is not found')
        addon_seats = _addon_seats_from_spec_line(
            addon_name,
            has_seat_token=(sep == ':' and bool(spec[2])),
            seat_part=seat_str,
            spec=spec,
            seat_label_for_errors=seat_str,
        )
        if permits and permits.allowed_add_ons is not None and len(permits.allowed_add_ons) > 0:
            if addon_name not in (x.lower() for x in permits.allowed_add_ons):
                raise errors.KeeperError(f'Managed Company add-on "{addon_name}" is not allowed')
        add_entry: Dict[str, Any] = {'add_on': spec[0]}
        if addon_seats > 0:
            add_entry['seats'] = addon_seats
        addons[addon_name] = add_entry

    for aon in remove_lines:
        addon_name = aon.strip().lower()
        spec = next((x for x in enterprise_constants.MSP_ADDONS if x[0] == addon_name), None)
        if spec is None:
            raise errors.KeeperError(f'Addon "{addon_name}" is not found')
        if addon_name in addons:
            del addons[addon_name]


def msp_update_managed_company(
    loader: enterprise_types.IEnterpriseLoader,
    *,
    managed_company: str,
    node_id: Optional[int] = None,
    new_name: Optional[str] = None,
    plan: Optional[str] = None,
    seats: Optional[int] = None,
    file_plan: Optional[str] = None,
    add_addons: Optional[List[str]] = None,
    remove_addons: Optional[List[str]] = None,
) -> int:
    """Update an existing managed company.

    :param managed_company: Managed company name or numeric enterprise id.
    :param node_id: When set, moves the MC under this enterprise node id.
    :param new_name: New display name for the managed company.
    :param plan: New product plan code (``MSP_PLANS`` code, e.g. ``business``).
    :param seats: New seat cap; ``-1`` for unlimited when permitted.
    :param file_plan: Storage plan code or label (same matching rules as ``msp_add_managed_company``).
    :param add_addons: ``ADDON`` or ``ADDON:SEATS`` entries to add or replace.
    :param remove_addons: Addon codes to remove.
    :return: Managed company enterprise id (from the API response).
    """
    enterprise_data = loader.enterprise_data
    auth = loader.keeper_auth

    flt = _parse_managed_company_filter(managed_company)
    if flt is None:
        raise errors.KeeperError('Managed company name or id is required')
    current = _find_managed_company(enterprise_data, flt)
    if current is None:
        raise errors.KeeperError(f'Managed Company "{managed_company}" not found')

    rq: Dict[str, Any] = {
        'command': _CMD_ENTERPRISE_UPDATE_BY_MSP,
        'enterprise_id': current.mc_enterprise_id,
        'enterprise_name': current.mc_enterprise_name,
        'product_id': current.product_id,
        'seats': current.number_of_seats,
    }

    if node_id is not None:
        rq['node_id'] = node_id

    if new_name:
        rq['enterprise_name'] = new_name.strip()

    permits = _first_msp_permits(enterprise_data)

    if plan is not None:
        _apply_update_rq_plan(rq, plan, permits)

    if isinstance(seats, int):
        _apply_update_rq_seats(rq, seats, permits)

    _apply_file_plan_fields_to_mc_update_rq(rq, file_plan, current, permits)

    addons = _selectable_addons_from_managed_company(current)
    add_list = add_addons if isinstance(add_addons, list) else []
    remove_list = remove_addons if isinstance(remove_addons, list) else []
    _apply_update_addon_mutations(addons, add_lines=add_list, remove_lines=remove_list, permits=permits)
    _assert_remote_browser_requires_connection_manager_update(addons)

    rq['add_ons'] = list(addons.values())
    rs = auth.execute_auth_command(rq)
    eid = int(rs.get('enterprise_id', current.mc_enterprise_id))
    msp_down(loader, reset=False)
    return eid


def msp_remove_managed_company(
    loader: enterprise_types.IEnterpriseLoader,
    *,
    managed_company: str,
) -> int:
    """Remove a managed company tenant.

    :param managed_company: Managed company name or numeric enterprise id.
    :return: The removed managed company enterprise id.
    """
    enterprise_data = loader.enterprise_data
    auth = loader.keeper_auth

    flt = _parse_managed_company_filter(managed_company)
    if flt is None:
        raise errors.KeeperError('Managed Company name or id is required')
    current = _find_managed_company(enterprise_data, flt)
    if current is None:
        raise errors.KeeperError(f'Managed Company "{managed_company}" not found')

    rq: Dict[str, Any] = {
        'command': _CMD_ENTERPRISE_REMOVE_BY_MSP,
        'enterprise_id': current.mc_enterprise_id,
    }
    auth.execute_auth_command(rq)
    eid = current.mc_enterprise_id
    msp_down(loader, reset=False)
    return eid


def _node_json_bytes_for_reencrypt(node: enterprise_types.Node, msp_tree_key: bytes) -> bytes:
    if node.encrypted_data:
        try:
            payload = _decrypt_encrypted_data(node.encrypted_data, _ENCRYPTED_BY_DATA_KEY, msp_tree_key)
        except Exception:
            payload = {_JSON_KEY_DISPLAYNAME: node.name or ''}
    else:
        payload = {_JSON_KEY_DISPLAYNAME: node.name or ''}
    return json.dumps(payload).encode('utf-8')


def _role_json_bytes_for_reencrypt(role: enterprise_types.Role, msp_tree_key: bytes) -> bytes:
    if role.key_type == _KEY_TYPE_NO_KEY:
        return json.dumps({_JSON_KEY_DISPLAYNAME: role.name or ''}).encode('utf-8')
    if role.encrypted_data:
        try:
            payload = _decrypt_encrypted_data(role.encrypted_data, role.key_type, msp_tree_key)
        except Exception:
            payload = {_JSON_KEY_DISPLAYNAME: role.name or ''}
    else:
        payload = {_JSON_KEY_DISPLAYNAME: role.name or ''}
    return json.dumps(payload).encode('utf-8')


def _user_reencrypt_payload(user: enterprise_types.User, msp_tree_key: bytes) -> Union[str, bytes]:
    """Returns either plaintext display name (no_key) or UTF-8 JSON bytes to encrypt with MC tree key."""
    if user.key_type == _KEY_TYPE_NO_KEY:
        if user.encrypted_data:
            return str(user.encrypted_data)
        return str(user.full_name or _UNKNOWN_USER_LABEL)
    if user.encrypted_data:
        try:
            payload = _decrypt_encrypted_data(user.encrypted_data, user.key_type, msp_tree_key)
        except Exception:
            payload = {_JSON_KEY_DISPLAYNAME: user.full_name or ''}
    else:
        payload = {_JSON_KEY_DISPLAYNAME: user.full_name or ''}
    return json.dumps(payload).encode('utf-8')


def _collect_convert_node_subtree(enterprise_data: enterprise_types.IEnterpriseData, msp_node_id: int) -> Tuple[List[int], Set[int], Set[int], Set[str], Set[int]]:
    node_tree: Dict[int, Set[int]] = {}
    for node in enterprise_data.nodes.get_all_entities():
        nid = node.node_id
        pid = node.parent_id
        if isinstance(pid, int) and isinstance(nid, int):
            if pid not in node_tree:
                node_tree[pid] = set()
            node_tree[pid].add(nid)
    all_subnodes: List[int] = [msp_node_id]
    pos = 0
    while pos < len(all_subnodes):
        nid = all_subnodes[pos]
        pos += 1
        if nid in node_tree:
            all_subnodes.extend(node_tree[nid])
    nodes_to_move = set(all_subnodes)
    roles_to_move = {r.role_id for r in enterprise_data.roles.get_all_entities() if r.node_id in nodes_to_move}
    teams_to_move = {t.team_uid for t in enterprise_data.teams.get_all_entities() if t.node_id in nodes_to_move}
    users_to_move = {u.enterprise_user_id for u in enterprise_data.users.get_all_entities() if u.node_id in nodes_to_move}
    return all_subnodes, nodes_to_move, roles_to_move, teams_to_move, users_to_move


def _validate_msp_convert_node(
    enterprise_data: enterprise_types.IEnterpriseData,
    *,
    nodes_to_move: Set[int],
    roles_to_move: Set[int],
    teams_to_move: Set[str],
    users_to_move: Set[int],
) -> List[str]:
    messages: List[str] = []
    role_lookup = {r.role_id: r for r in enterprise_data.roles.get_all_entities()}
    team_lookup = {t.team_uid: t for t in enterprise_data.teams.get_all_entities()}
    user_lookup = {u.enterprise_user_id: u for u in enterprise_data.users.get_all_entities()}

    def node_path(nid: int) -> str:
        return _node_path(enterprise_data, nid, omit_root=False)

    for bridge in enterprise_data.bridges.get_all_entities():
        if bridge.node_id in nodes_to_move:
            messages.append(
                f'Remove bridge provisioning before conversion from node {node_path(bridge.node_id)}')
    for scim in enterprise_data.scims.get_all_entities():
        if scim.node_id in nodes_to_move:
            messages.append(
                f'Remove SCIM provisioning before conversion from node {node_path(scim.node_id)}')
    for sso in enterprise_data.sso_services.get_all_entities():
        if sso.node_id in nodes_to_move:
            messages.append(
                f'Remove SSO provisioning before conversion from node {node_path(sso.node_id)}')
    for email in enterprise_data.email_provision.get_all_entities():
        if email.node_id in nodes_to_move:
            messages.append(
                f'Remove email provisioning before conversion from node {node_path(email.node_id)}')
    for mc in enterprise_data.managed_companies.get_all_entities():
        if mc.msp_node_id in nodes_to_move:
            messages.append(
                f'Remove managed company before conversion from node {node_path(mc.msp_node_id)}')
    for qt in enterprise_data.queued_teams.get_all_entities():
        if qt.node_id in nodes_to_move:
            messages.append(
                f'Remove queued team {qt.name} before conversion from node {node_path(qt.node_id)}')

    for uid in users_to_move:
        user = user_lookup.get(uid)
        if user and user.status == 'invited':
            messages.append(f'Pending user {user.username} must be removed')

    for ru in enterprise_data.role_users.get_all_links():
        move_user = ru.enterprise_user_id in users_to_move
        move_role = ru.role_id in roles_to_move
        if move_role != move_user:
            user = user_lookup.get(ru.enterprise_user_id)
            username = (user.username if user else '') or str(ru.enterprise_user_id)
            role = role_lookup.get(ru.role_id)
            rolename = (role.name if role else '') or str(ru.role_id)
            messages.append(f'Conflicting role membership: User: {username}, Role: {rolename}')

    for rt in enterprise_data.role_teams.get_all_links():
        move_team = rt.team_uid in teams_to_move
        move_role = rt.role_id in roles_to_move
        if move_role != move_team:
            team = team_lookup.get(rt.team_uid)
            teamname = (team.name if team else rt.team_uid) or rt.team_uid
            role = role_lookup.get(rt.role_id)
            rolename = (role.name if role else '') or str(rt.role_id)
            messages.append(f'Conflicting role membership: Team: {teamname}, Role: {rolename}')

    for tu in enterprise_data.team_users.get_all_links():
        move_user = tu.enterprise_user_id in users_to_move
        move_team = tu.team_uid in teams_to_move
        if move_team != move_user:
            user = user_lookup.get(tu.enterprise_user_id)
            username = (user.username if user else '') or str(tu.enterprise_user_id)
            team = team_lookup.get(tu.team_uid)
            teamname = (team.name if team else '') or tu.team_uid
            messages.append(f'Conflicting team membership: User: {username}, Team: {teamname}')

    for mn in enterprise_data.managed_nodes.get_all_links():
        move_role = mn.role_id in roles_to_move
        move_node = mn.managed_node_id in nodes_to_move
        if move_role != move_node:
            role = role_lookup.get(mn.role_id)
            rolename = (role.name if role else '') or str(mn.role_id)
            nodename = node_path(mn.managed_node_id)
            messages.append(f'Conflicting admin role management: Node: {nodename}, Role: {rolename}')

    return messages


def msp_convert_node(
    loader: enterprise_types.IEnterpriseLoader,
    *,
    node_id: int,
    seats: Optional[int] = None,
    plan: Optional[str] = None,
) -> int:
    """Convert an MSP enterprise subtree rooted at ``node_id`` into a managed company.

    Validates the subtree (no bridges, SCIM, SSO on affected nodes, no straddling role/team links, etc.),
    optionally registers a new managed company, logs into the MC, re-encrypts node/role/user/team keys for
    the MC tree key, calls ``enterprise/node_to_managed_company``, then refreshes MSP data.

    :param loader: MSP enterprise loader.
    :param node_id: Root of the subtree to convert (must not be the enterprise root).
    :param seats: Seat count for a newly registered MC; adjusted upward to user count and defaulted.
    :param plan: Product plan code when registering a new MC (default ``business``).
    :return: Managed company enterprise id.
    """
    enterprise_data = loader.enterprise_data
    auth = loader.keeper_auth
    msp_tree_key = enterprise_data.enterprise_info.tree_key
    root_id = enterprise_data.root_node.node_id

    if node_id == root_id:
        raise errors.KeeperError('Root node cannot be converted')

    all_subnodes, nodes_to_move, roles_to_move, teams_to_move, users_to_move = _collect_convert_node_subtree(
        enterprise_data, node_id)

    err_list = _validate_msp_convert_node(
        enterprise_data,
        nodes_to_move=nodes_to_move,
        roles_to_move=roles_to_move,
        teams_to_move=teams_to_move,
        users_to_move=users_to_move,
    )
    if err_list:
        raise errors.KeeperError('\n'.join(err_list))

    msp_node = enterprise_data.nodes.get_entity(node_id)
    if not msp_node:
        raise errors.KeeperError(f'Node id {node_id} not found')
    msp_node_name = (msp_node.name or '').strip()
    if not msp_node_name:
        raise errors.KeeperError('Node has no display name; cannot convert to a managed company')

    seat_val = 0 if seats is None else int(seats)
    if seat_val < len(users_to_move):
        seat_val = len(users_to_move)
    if seat_val == 0:
        seat_val = 1

    plan_label = plan or _DEFAULT_CONVERT_PLAN
    plan_name = plan_label.strip().lower()
    product_plan = _lookup_msp_product_plan(plan_label)
    if not product_plan:
        raise errors.KeeperError(f'Managed Company plan "{plan_name}" is not found')

    permits = _first_msp_permits(enterprise_data)
    _assert_mc_product_plan_allowed(plan_label, plan_name, permits)

    if seat_val < 0:
        if permits and not permits.allow_unlimited_licenses:
            raise errors.KeeperError('Managed Company unlimited licences are not allowed')
        seat_val = _INT32_MAX

    mc_existing = next(
        (x for x in enterprise_data.managed_companies.get_all_entities() if x.mc_enterprise_name == msp_node_name),
        None,
    )
    mc_id: int

    if mc_existing is None:
        new_mc_tree_key = utils.generate_aes_key()
        rq: Dict[str, Any] = {
            'command': _CMD_ENTERPRISE_REGISTRATION_BY_MSP,
            'node_id': root_id,
            'seats': seat_val,
            'product_id': product_plan[1],
            'enterprise_name': msp_node_name,
            **_new_mc_encrypted_registration_fields(new_mc_tree_key, msp_tree_key),
        }
        rs = auth.execute_auth_command(rq)
        mc_id = int(rs.get('enterprise_id', -1))
        if mc_id < 0:
            raise errors.KeeperError('Managed company registration did not return an enterprise id')
    else:
        mc_id = mc_existing.mc_enterprise_id

    mc_auth, mc_tree_key_login = login_to_managed_company(loader, mc_id)
    mc_tree_key = mc_tree_key_login

    mc_rq = enterprise_pb2.NodeToManagedCompanyRequest()
    mc_rq.companyId = mc_id

    for nid in all_subnodes:
        node = enterprise_data.nodes.get_entity(nid)
        if not node:
            continue
        red = enterprise_pb2.ReEncryptedData()
        red.id = nid
        raw = _node_json_bytes_for_reencrypt(node, msp_tree_key)
        red.data = utils.base64_url_encode(crypto.encrypt_aes_v1(raw, mc_tree_key))
        mc_rq.nodes.append(red)

    for role_id in roles_to_move:
        role = enterprise_data.roles.get_entity(role_id)
        if not role:
            continue
        red = enterprise_pb2.ReEncryptedData()
        red.id = role_id
        raw = _role_json_bytes_for_reencrypt(role, msp_tree_key)
        red.data = utils.base64_url_encode(crypto.encrypt_aes_v1(raw, mc_tree_key))
        mc_rq.roles.append(red)

    for user_id in users_to_move:
        user = enterprise_data.users.get_entity(user_id)
        if not user:
            continue
        red = enterprise_pb2.ReEncryptedData()
        red.id = user_id
        payload = _user_reencrypt_payload(user, msp_tree_key)
        if isinstance(payload, str):
            red.data = payload
        else:
            red.data = utils.base64_url_encode(crypto.encrypt_aes_v1(payload, mc_tree_key))
        mc_rq.users.append(red)

    admin_role_ids = {mn.role_id for mn in enterprise_data.managed_nodes.get_all_links() if mn.role_id in roles_to_move}
    if admin_role_ids:
        loader.load_role_keys(admin_role_ids)
        for rid in sorted(admin_role_ids):
            role_key = loader.get_role_keys(rid)
            if role_key:
                rerk = enterprise_pb2.ReEncryptedRoleKey()
                rerk.role_id = rid
                rerk.encryptedRoleKey = crypto.encrypt_aes_v2(role_key, mc_tree_key)
                mc_rq.roleKeys.append(rerk)

    for team_uid in teams_to_move:
        team = enterprise_data.teams.get_entity(team_uid)
        if not team:
            continue
        etkr = enterprise_pb2.EncryptedTeamKeyRequest()
        etkr.teamUid = utils.base64_url_decode(team.team_uid)
        if team.encrypted_team_key:
            team_key = crypto.decrypt_aes_v2(team.encrypted_team_key, msp_tree_key)
            etkr.encryptedTeamKey = crypto.encrypt_aes_v2(team_key, mc_tree_key)
        else:
            etkr.force = True
        mc_rq.teamKeys.append(etkr)

    dk_rq = APIRequest_pb2.UserDataKeyByNodeRequest()
    dk_rq.nodeIds.extend(nodes_to_move)
    dk_rs = auth.execute_auth_rest(
        _REST_USER_DATA_KEY_BY_NODE,
        dk_rq,
        response_type=enterprise_pb2.EnterpriseUserDataKeysByNodeResponse,
    )

    msp_ec_private = enterprise_data.enterprise_info.ec_private_key
    if dk_rs and len(dk_rs.keys) > 0 and msp_ec_private:
        mc_pk_rs = mc_auth.execute_auth_rest(
            _REST_MC_PUBLIC_KEY,
            None,
            response_type=breachwatch_pb2.EnterprisePublicKeyResponse,
        )
        if mc_pk_rs and mc_pk_rs.enterpriseECCPublicKey:
            mc_public_key = crypto.load_ec_public_key(mc_pk_rs.enterpriseECCPublicKey)
            for dk_node in dk_rs.keys:
                for dk in dk_node.keys:
                    if dk.keyTypeId == _USER_DATA_KEY_TYPE_ID_ECC and dk.enterpriseUserId in users_to_move:
                        encrypted_key = crypto.decrypt_ec(dk.userEncryptedDataKey, msp_ec_private)
                        encrypted_key = crypto.encrypt_ec(encrypted_key, mc_public_key)
                        re_dk = enterprise_pb2.ReEncryptedUserDataKey()
                        re_dk.enterpriseUserId = dk.enterpriseUserId
                        re_dk.userEncryptedDataKey = encrypted_key
                        mc_rq.usersDataKeys.append(re_dk)

    auth.execute_auth_rest(_REST_NODE_TO_MANAGED_COMPANY, mc_rq, response_type=None)
    msp_down(loader, reset=False)
    return mc_id


def _find_roles_by_name_or_id(
    enterprise_data: enterprise_types.IEnterpriseData,
    name_or_id: str,
) -> List[enterprise_types.Role]:
    token = (name_or_id or '').strip()
    if token.isdigit():
        role = enterprise_data.roles.get_entity(int(token))
        return [role] if role is not None else []
    role_name = token.casefold()
    return [x for x in enterprise_data.roles.get_all_entities() if x.name.casefold() == role_name]


def _to_enforcement_map_for_roles(
    role_enforcements: List[enterprise_types.RoleEnforcement],
) -> Dict[int, Dict[str, str]]:
    result: Dict[int, Dict[str, str]] = {}
    for enf in role_enforcements:
        if enf.role_id not in result:
            result[enf.role_id] = {}
        result[enf.role_id][enf.enforcement_type.lower()] = enf.value
    return result


def _extract_mc_enterprise_payload(rs: Dict[str, Any]) -> Dict[str, Any]:
    enterprise = rs.get('enterprise')
    if isinstance(enterprise, dict):
        return enterprise
    return rs


def _mc_payload_root_node_id(enterprise_payload: Dict[str, Any]) -> Optional[int]:
    for node in enterprise_payload.get('nodes', []) or []:
        if not node.get('parent_id'):
            node_id = node.get('node_id')
            if isinstance(node_id, int):
                return node_id
    return None


def _mc_payload_role_name(role_payload: Dict[str, Any]) -> str:
    data = role_payload.get('data')
    if isinstance(data, dict):
        display_name = data.get(_JSON_KEY_DISPLAYNAME)
        if isinstance(display_name, str):
            return display_name
    return ''


def _allocate_enterprise_id(auth: keeper_auth.KeeperAuth) -> int:
    rs = auth.execute_auth_command({'command': _CMD_ENTERPRISE_ALLOCATE_IDS, 'number_requested': 1})
    base_id = int(rs.get('base_id', 0))
    allocated = int(rs.get('number_allocated', 0))
    if allocated < 1:
        raise errors.KeeperError('Unable to allocate enterprise id')
    return base_id + 1


def _coerce_msp_copy_enforcement_value(name: str, value: Any) -> Any:
    enforcement_type = enterprise_constants.ENFORCEMENTS.get(name.lower())
    if not enforcement_type:
        return value
    if enforcement_type == 'long':
        try:
            return int(value)
        except Exception as err:
            raise errors.KeeperError(f'Enforcement {name}: invalid integer value: {value}') from err
    if enforcement_type == 'boolean':
        if isinstance(value, bool):
            return value
        return str(value).lower() == 'true'
    if enforcement_type == 'account_share':
        return None
    if enforcement_type in {'record_types', 'json', 'jsonarray'}:
        if isinstance(value, (dict, list)):
            return value
        return json.loads(str(value))
    return value


def msp_copy_role(
    loader: enterprise_types.IEnterpriseLoader,
    *,
    roles: List[str],
    managed_companies: List[str],
) -> Set[int]:
    """Copy role enforcements from MSP to one or more managed companies.

    Roles are matched by id or case-insensitive exact name in the MSP enterprise. For each target MC,
    role names are matched case-insensitively; missing roles are created. Enforcements are then synchronized:
    add/update to match source and remove extras from destination role.
    """
    enterprise_data = loader.enterprise_data
    msp_tree_key = enterprise_data.enterprise_info.tree_key
    logger = utils.get_logger()

    role_inputs = [str(x).strip() for x in (roles or []) if str(x).strip()]
    if len(role_inputs) == 0:
        raise errors.KeeperError('Source role parameter is required')
    mc_inputs = [str(x).strip() for x in (managed_companies or []) if str(x).strip()]
    if len(mc_inputs) == 0:
        raise errors.KeeperError('Managed company parameter is required')

    source_roles: Dict[int, enterprise_types.Role] = {}
    for role_token in role_inputs:
        matched_roles = _find_roles_by_name_or_id(enterprise_data, role_token)
        if len(matched_roles) == 1:
            source_roles[matched_roles[0].role_id] = matched_roles[0]
        elif len(matched_roles) > 1:
            raise errors.KeeperError(f'There are more than one roles with name "{role_token}". Use Role ID')
        else:
            raise errors.KeeperError(f'Role "{role_token}" not found')

    src_role_enforcements = _to_enforcement_map_for_roles(list(enterprise_data.role_enforcements.get_all_links()))
    unique_mcs: Dict[int, enterprise_types.ManagedCompany] = {}
    for mc_input in mc_inputs:
        mc_filter = _parse_managed_company_filter(mc_input)
        if mc_filter is None:
            continue
        mc = _find_managed_company(enterprise_data, mc_filter)
        if mc is None:
            raise errors.KeeperError(f'Managed Company "{mc_input}" not found')
        unique_mcs[mc.mc_enterprise_id] = mc

    synced_mc_ids: Set[int] = set()
    for mc in unique_mcs.values():
        mc_id = mc.mc_enterprise_id
        mc_auth, mc_tree_key = login_to_managed_company(loader, mc_id)
        mc_rs = mc_auth.execute_auth_command({'command': _CMD_QUERY_ENTERPRISE})
        if not isinstance(mc_rs, dict):
            raise errors.KeeperError(f'MC {mc_id}: query_enterprise response is invalid')
        mc_payload = _extract_mc_enterprise_payload(mc_rs)
        root_node_id = _mc_payload_root_node_id(mc_payload)
        if not isinstance(root_node_id, int):
            raise errors.KeeperError(f'MC {mc_id}: root node is not found')

        dst_roles = list(mc_payload.get('roles') or [])
        dst_role_enforcements: Dict[int, Dict[str, Any]] = {}
        for item in mc_payload.get('role_enforcements') or []:
            role_id = item.get('role_id')
            enforcements = item.get('enforcements')
            if isinstance(role_id, int) and isinstance(enforcements, dict):
                dst_role_enforcements[role_id] = dict(enforcements)

        mc_rqs: List[Dict[str, Any]] = []
        for src_role in source_roles.values():
            src_role_id = src_role.role_id
            role_name = src_role.name or ''
            if not role_name:
                continue

            matches = [r for r in dst_roles if _mc_payload_role_name(r).casefold() == role_name.casefold()]
            if len(matches) > 1:
                logger.warning('MC #%s: There are more than one roles with name "%s". Skipping', mc_id, role_name)
                continue
            if len(matches) == 1:
                dst_role_id = int(matches[0].get('role_id') or 0)
                if dst_role_id <= 0:
                    logger.warning('MC #%s: Role "%s" has invalid role id. Skipping', mc_id, role_name)
                    continue
            else:
                dst_role_id = _allocate_enterprise_id(mc_auth)
                role_data = json.dumps({_JSON_KEY_DISPLAYNAME: role_name}).encode('utf-8')
                mc_rqs.append({
                    'command': _CMD_ROLE_ADD,
                    'role_id': dst_role_id,
                    'node_id': root_node_id,
                    'encrypted_data': utils.base64_url_encode(crypto.encrypt_aes_v1(role_data, mc_tree_key)),
                    'visible_below': src_role.visible_below,
                    'new_user_inherit': src_role.new_user_inherit,
                })
                dst_roles.append({'role_id': dst_role_id, 'data': {_JSON_KEY_DISPLAYNAME: role_name}})

            src_enforcements = dict(src_role_enforcements.get(src_role_id) or {})
            stale_dst_enforcements = dict(dst_role_enforcements.get(dst_role_id) or {})
            for enforcement_name, src_value in src_enforcements.items():
                if enforcement_name in stale_dst_enforcements:
                    dst_value = stale_dst_enforcements.pop(enforcement_name)
                    if src_value == dst_value:
                        continue
                    command = _CMD_ROLE_ENFORCEMENT_UPDATE
                else:
                    command = _CMD_ROLE_ENFORCEMENT_ADD
                try:
                    value = _coerce_msp_copy_enforcement_value(enforcement_name, src_value)
                    if value is None:
                        continue
                    rq: Dict[str, Any] = {
                        'command': command,
                        'role_id': dst_role_id,
                        'enforcement': enforcement_name,
                    }
                    if not isinstance(value, bool):
                        rq['value'] = value
                    mc_rqs.append(rq)
                except Exception as err:
                    logger.warning('Role %s: Enforcement %s: %s', role_name, enforcement_name, err)

            for enforcement_name in stale_dst_enforcements.keys():
                mc_rqs.append({
                    'command': _CMD_ROLE_ENFORCEMENT_REMOVE,
                    'role_id': dst_role_id,
                    'enforcement': enforcement_name,
                })

        if mc_rqs:
            mc_auth.execute_batch(mc_rqs)
        logger.info('MC %s: Roles are in sync', mc_id)
        synced_mc_ids.add(mc_id)

    return synced_mc_ids
