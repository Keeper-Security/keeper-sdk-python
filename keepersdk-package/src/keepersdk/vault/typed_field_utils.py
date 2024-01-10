from typing import Optional

class TypedFieldMixin:
    week_days = ('SUNDAY', 'MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY')
    occurrences = ('FIRST', 'SECOND', 'THIRD', 'FOURTH', 'LAST')
    months = ('JANUARY', 'FEBRUARY', 'MARCH', 'APRIL', 'MAY', 'JUNE', 'JULY', 'AUGUST', 'SEPTEMBER', 'OCTOBER',
              'NOVEMBER', 'DECEMBER')

    @staticmethod
    def get_cron_week_day(text: Optional[str]) -> Optional[int]:
        if isinstance(text, str):
            try:
                return TypedFieldMixin.week_days.index(text.upper())
            except:
                pass

    @staticmethod
    def get_cron_occurrence(text: Optional[str]) -> Optional[int]:
        if isinstance(text, str):
            try:
                idx = TypedFieldMixin.occurrences.index(text.upper())
                idx += 1
                if idx > 4:
                    idx = 4
                return idx
            except:
                pass

    @staticmethod
    def get_cron_month(text: Optional[str]) -> Optional[int]:
        if isinstance(text, str):
            try:
                m = TypedFieldMixin.months.index(text.upper())
                return m + 1
            except:
                pass

    @staticmethod
    def get_cron_month_day(text: Optional[str]) -> Optional[int]:
        if isinstance(text, str) and text.isnumeric():
            day = int(text)
            if day < 1:
                day = 1
            elif day > 28:
                day = 28
            return day

    @staticmethod
    def export_host_field(value: dict)  -> Optional[str]:
        if isinstance(value, dict):
            host = value.get('hostName') or ''
            port = value.get('port') or ''
            if host or port:
                if port:
                    host += ':' + port
            return host

    @staticmethod
    def export_phone_field(value: dict) -> Optional[str]:
        if isinstance(value, dict):
            phone = value.get('type') or ''
            if phone:
                phone += ':'
            region = value.get('region') or ''
            if region:
                if len(region) == 2 and region.isalpha():
                    pass
                elif region.isnumeric():
                    region = '+' + region
                else:
                    region = ''
                if region:
                    phone += '  ' + region
            number = (value.get('number') or '').replace(' ', '-')
            if number:
                phone += ' ' + number
            ext = (value.get('ext') or '').replace(' ', '-')
            if ext:
                phone += ' ' + ext
            return phone

    @staticmethod
    def export_name_field(value: dict) -> Optional[str]:
        if isinstance(value, dict):
            first_name = value.get('first') or ''
            middle_name = value.get('middle') or ''
            name = value.get('last') or ''
            if first_name or middle_name or name:
                name = f'{name}, {first_name}'
                if middle_name:
                    name += ' ' + middle_name
            return name

    @staticmethod
    def export_address_field(value: dict) -> Optional[str]:
        if isinstance(value, dict):
            address = value.get('street1', '').replace(',', '.')
            street2 = value.get('street2', '').replace(',', '.')
            if street2:
                address += ' ' + street2
            city = value.get('city', '').replace(',', '.')
            if city:
                address += ', ' + city
                state = value.get('state', '').replace(',', '.')
                zip_code = value.get('zip', '').replace(',', '.')
                if state or zip_code:
                    address += ', ' + state + ' ' + zip_code
                    country = value.get('country', '').replace(',', '.')
                    if country:
                        address += ', ' + country
            return address

    @staticmethod
    def export_q_and_a_field(value: dict) -> Optional[str]:
        if isinstance(value, dict):
            q = value.get('question', '').replace('?', '')
            a = value.get('answer', '')
            return f'{q}? {a}'.strip()

    @staticmethod
    def export_card_field(value: dict) -> Optional[str]:
        if isinstance(value, dict):
            comps = []
            number = value.get('cardNumber')
            if number:
                comps.append(number)
            expiration = value.get('cardExpirationDate')
            if expiration:
                comps.append(expiration)
            cvv = value.get('cardSecurityCode')
            if cvv:
                comps.append(cvv)
            if comps:
                return ' '.join(comps)

    @staticmethod
    def export_account_field(value: dict) -> Optional[str]:
        if isinstance(value, dict):
            account_type = value.get('accountType', '').replace(' ', '')
            routing = value.get('routingNumber', '').replace(' ', '')
            account_number = value.get('accountNumber', '').replace(' ', '')
            if routing or account_number:
                comps = []
                if account_type:
                    comps.append(account_type)
                if routing:
                    comps.append(routing)
                if account_number:
                    comps.append(account_number)
                if comps:
                    return ' '.join(comps)

    @staticmethod
    def export_ssh_key_field(value: dict) -> Optional[str]:
        if isinstance(value, dict):
            return value.get('privateKey', '')

    @staticmethod
    def export_schedule_field(value: dict) -> Optional[str]:
        if isinstance(value, dict):
            schedule_type = value.get('type')
            hour = '0'
            minute = '0'
            day = '*'
            month = '*'
            week_day = '*'
            utc_time = value.get('utcTime') or ''
            if utc_time:
                comps = utc_time.split(':')
                if len(comps) == 2:
                    if comps[0].isnumeric():
                        h = int(comps[0])
                        if 0 <= h <= 23:
                            hour = str(h)
                    if comps[1].isnumeric():
                        m = int(comps[1])
                        if 0 <= m <= 59:
                            minute = str(m)

            if schedule_type == 'DAILY':
                interval = value.get('intervalCount') or 0
                if interval > 1:
                    if interval > 28:
                        interval = 28
                    day = f'*/{interval}'
            elif schedule_type == 'WEEKLY':
                week_day = str(TypedFieldMixin.get_cron_week_day(value.get('weekday')) or 1)
            elif schedule_type == 'MONTHLY_BY_DAY':
                day = str(TypedFieldMixin.get_cron_month_day(value.get('monthDay')) or 1)
            elif schedule_type == 'MONTHLY_BY_WEEKDAY':
                wd = str(TypedFieldMixin.get_cron_week_day(value.get('weekday')) or 1)
                occ = str(TypedFieldMixin.get_cron_occurrence(value.get('occurrence')) or 1)
                week_day = f'{wd}#{occ}'
            elif schedule_type == 'YEARLY':
                month = str(TypedFieldMixin.get_cron_month(value.get('month')) or 1)
                day = str(TypedFieldMixin.get_cron_month_day(value.get('monthDay')) or 1)
            else:
                return ''

            return f'{minute} {hour} {day} {month} {week_day}'

    @staticmethod
    def import_host_field(value: str) -> Optional[dict]:
        if isinstance(value, str):
            host, _, port = value.partition(':')
            return {
                'hostName': host.strip(),
                'port': port.strip()
            }

    @staticmethod
    def import_phone_field(value: str) -> Optional[dict]:
        if isinstance(value, str):
            region = ''
            number = ''
            ext = ''
            phone_type, _, rest = value.partition(':')
            if not rest:
                rest = phone_type
                phone_type = ''
            comps = rest.strip().split(' ')
            for comp in comps:
                comp = comp.strip()
                if comp.isalpha():
                    if len(comp) == 2:
                        if not region:
                            region = comp
                    elif not phone_type:
                        phone_type = comp
                elif len(comp) >= 6:
                    if not number:
                        number = comp
                elif not ext:
                    ext = comp
            result = {
                'type': '',
                'region': '',
                'number': number.strip(),
                'ext': ext.strip()
            }
            phone_type = phone_type.strip()
            region = region.strip()
            if phone_type:
                result['type'] = phone_type
            if region:
                result['region'] = region
            return result

    @staticmethod
    def import_name_field(value: str) -> Optional[dict]:
        if isinstance(value, str):
            first = ''
            middle = ''
            last = ''
            comma_pos = value.find(',')
            if comma_pos >= 0:
                last = value[:comma_pos]
                rest = value[comma_pos+1:]
            else:
                space_pos = value.rfind(' ')
                if space_pos >= 0:
                    last = value[space_pos+1:]
                    rest = value[:space_pos]
                else:
                    last = value
                    rest = ''
            rest = rest.strip()
            if rest:
                space_pos = rest.rfind(' ')
                if space_pos >= 0:
                    middle = rest[space_pos+1:]
                    first = rest[:space_pos]
                else:
                    middle = ''
                    first = rest

            return {
                'first': first.strip(),
                'middle': middle.strip(),
                'last': last.strip(),
            }

    @staticmethod
    def import_address_field(value: str) -> Optional[dict]:
        if isinstance(value, str):
            comps = value.split(',')
            street1 = comps[0].strip() if len(comps) > 0 else ''
            city = comps[1].strip() if len(comps) > 1 else ''
            state, _, zip_code = comps[2].strip().partition(' ') if len(comps) > 2 else ('', '', '')
            if state and not zip_code:
                if state.isnumeric():
                    zip_code = state
                    state = ''
            country = comps[3].strip() if len(comps) > 3 else ''

            return {
                'street1': street1,
                'street2': '',
                'city': city,
                'state': state,
                'zip': zip_code,
                'country': country
            }

    @staticmethod
    def import_q_and_a_field(value: str) -> Optional[dict]:
        if isinstance(value, str):
            q, sign, a = value.partition('?')
            return {
                'question': q.strip() + '?',
                'answer': a.strip(),
            }

    @staticmethod
    def import_card_field(value: str) -> Optional[dict]:
        if isinstance(value, str):
            comps = value.split(' ')
            number = ''
            expiration = ''
            cvv = ''
            for comp in comps:
                comp = comp.strip()
                if comp:
                    if len(comp) > 10:
                        number = comp
                    elif comp.find('/') >= 0:
                        expiration = comp
                    elif len(comp) <= 6:
                        cvv = comp
            if number or expiration or cvv:
                return {
                    'cardNumber': number,
                    'cardExpirationDate': expiration,
                    'cardSecurityCode':  cvv,
                }

    @staticmethod
    def import_account_field(value: str) -> Optional[dict]:
        if isinstance(value, str):
            account_type = ''
            routing = ''
            account_number = ''
            comps = value.split()
            for comp in comps:
                comp = comp.strip()
                if comp.isnumeric():
                    if not routing:
                        routing = comp
                    elif not account_number:
                        account_number = comp
                else:
                    if not account_type:
                        account_type = comp
            if routing or account_number:
                return {
                    'accountType': account_type,
                    'routingNumber': routing,
                    'accountNumber': account_number
                }

    @staticmethod
    def import_ssh_key_field(value: str) -> Optional[dict]:
        if isinstance(value, str):
            return {
                'privateKey': value.replace('\\n', '\n'),
                'publicKey': ''
            }

    @staticmethod
    def import_schedule_field(value: str) -> Optional[dict]:
        if isinstance(value, str) and len(value) > 0:
            comps = value.split(' ')
            if len(comps) >= 3:
                schedule = None
                if len(comps) < 4:
                    comps.insert(0, '0')
                if len(comps) < 5:
                    comps.insert(0, '0')
                minute = int(comps[0]) if comps[0].isnumeric() else 0
                if minute < 0 or minute > 59:
                    minute = 0
                hour = int(comps[1]) if comps[1].isnumeric() else 0
                if hour < 0 or hour > 23:
                    hour = 0
                utc_time = f'{hour:02}:{minute:02}'
                if comps[3] == '*' and comps[4] == '*':  # daily
                    if comps[2].isnumeric():
                        schedule = {
                            'type': 'MONTHLY_BY_DAY',
                            'utcTime': utc_time,
                            'monthDay': int(comps[2])
                        }
                    else:
                        interval = 1
                        if comps[2].startswith('*/'):
                            intr = comps[2][2:]
                            if intr.isnumeric():
                                interval = int(intr)
                        schedule = {
                            'type': 'DAILY',
                            'utcTime': utc_time,
                            'intervalCount': interval
                        }
                elif comps[4] != '*':  # day of week
                    if comps[4].isnumeric():
                        wd = int(comps[4])
                        if wd < 0 or wd > len(TypedFieldMixin.week_days):
                            wd = 1
                        schedule = {
                            'type': 'WEEKLY',
                            'utcTime': utc_time,
                            'weekday': TypedFieldMixin.week_days[wd]
                        }
                    else:
                        wd_comps = comps[4].split('#')
                        if len(wd_comps) == 2 and wd_comps[0].isnumeric() and wd_comps[1].isnumeric():
                            wd = int(wd_comps[0])
                            if wd < 0 or wd > len(TypedFieldMixin.week_days):
                                wd = 1
                            occ = int(wd_comps[1])
                            if occ < 0 or occ >= len(TypedFieldMixin.occurrences):
                                occ = 0
                            schedule = {
                                'type': 'MONTHLY_BY_WEEKDAY',
                                'utcTime': utc_time,
                                'weekday': TypedFieldMixin.week_days[wd],
                                'occurrence': TypedFieldMixin.occurrences[occ]
                            }
                elif comps[2].isnumeric() and comps[3].isnumeric():  # day of year
                    mm = int(comps[4])
                    if mm > 0:
                        mm -= 1
                        if mm >= len(TypedFieldMixin.months):
                            mm = len(TypedFieldMixin.months) - 1
                    else:
                        mm = 0
                    schedule = {
                        'type': 'YEARLY',
                        'utcTime': utc_time,
                        'month': TypedFieldMixin.months[mm],
                        'monthday': int(comps[3])
                    }
                return schedule
