#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from ..proto import APIRequest_pb2
from . import auth


def channel_keeper_to_sdk(channel_type):      # type: (int) -> auth.TwoFactorChannel
    if channel_type == APIRequest_pb2.TWO_FA_CT_TOTP:
        return auth.TwoFactorChannel.Authenticator
    if channel_type == APIRequest_pb2.TWO_FA_CT_SMS:
        return auth.TwoFactorChannel.TextMessage
    if channel_type == APIRequest_pb2.TWO_FA_CT_DUO:
        return auth.TwoFactorChannel.DuoSecurity
    if channel_type == APIRequest_pb2.TWO_FA_CT_RSA:
        return auth.TwoFactorChannel.RSASecurID
    if channel_type == APIRequest_pb2.TWO_FA_CT_WEBAUTHN:
        return auth.TwoFactorChannel.SecurityKey
    if channel_type == APIRequest_pb2.TWO_FA_CT_DNA:
        return auth.TwoFactorChannel.KeeperDNA
    if channel_type == APIRequest_pb2.TWO_FA_CT_BACKUP:
        return auth.TwoFactorChannel.Backup
    return auth.TwoFactorChannel.Other


def duration_keeper_to_sdk(duration):       # type: (int) -> auth.TwoFactorDuration
    if duration in {APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY, APIRequest_pb2.TWO_FA_EXP_5_MINUTES}:
        return auth.TwoFactorDuration.EveryLogin
    if duration in {APIRequest_pb2.TWO_FA_EXP_12_HOURS, APIRequest_pb2.TWO_FA_EXP_24_HOURS}:
        return auth.TwoFactorDuration.EveryDay
    if duration == APIRequest_pb2.TWO_FA_EXP_30_DAYS:
        return auth.TwoFactorDuration.Every30Days
    return auth.TwoFactorDuration.Forever


def duration_sdk_to_keeper(duration):       # type: (auth.TwoFactorDuration) -> int
    if duration == auth.TwoFactorDuration.EveryLogin:
        return APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY
    if duration == auth.TwoFactorDuration.EveryDay:
        return APIRequest_pb2.TWO_FA_EXP_24_HOURS
    if duration == auth.TwoFactorDuration.Every30Days:
        return APIRequest_pb2.TWO_FA_EXP_30_DAYS
    if duration == auth.TwoFactorDuration.Forever:
        return APIRequest_pb2.TWO_FA_EXP_NEVER
    return APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY


def duo_capability_to_sdk(capability):
    if capability == 'push':
        return auth.TwoFactorPushAction.DuoPush
    if capability == 'sms':
        return auth.TwoFactorPushAction.DuoTextMessage
    if capability == 'phone':
        return auth.TwoFactorPushAction.DuoVoiceCall
    return ''


def tfa_action_sdk_to_keeper(action):   # type: (auth.TwoFactorPushAction) -> int
    if action == auth.TwoFactorPushAction.DuoPush:
        return APIRequest_pb2.TWO_FA_PUSH_DUO_PUSH
    if action == auth.TwoFactorPushAction.DuoTextMessage:
        return APIRequest_pb2.TWO_FA_PUSH_DUO_TEXT
    if action == auth.TwoFactorPushAction.DuoVoiceCall:
        return APIRequest_pb2.TWO_FA_PUSH_DUO_CALL
    if action == auth.TwoFactorPushAction.TextMessage:
        return APIRequest_pb2.TWO_FA_PUSH_SMS
    if action == auth.TwoFactorPushAction.KeeperDna:
        return APIRequest_pb2.TWO_FA_PUSH_KEEPER
    return APIRequest_pb2.TWO_FA_PUSH_NONE


def tfa_value_type_for_channel(channel_type):   # type: (auth.TwoFactorChannel) -> int
    if channel_type == auth.TwoFactorChannel.Authenticator:
        return APIRequest_pb2.TWO_FA_CODE_TOTP
    if channel_type == auth.TwoFactorChannel.TextMessage:
        return APIRequest_pb2.TWO_FA_CODE_SMS
    if channel_type == auth.TwoFactorChannel.DuoSecurity:
        return APIRequest_pb2.TWO_FA_CODE_DUO
    if channel_type == auth.TwoFactorChannel.RSASecurID:
        return APIRequest_pb2.TWO_FA_CODE_RSA
    if channel_type == auth.TwoFactorChannel.SecurityKey:
        return APIRequest_pb2.TWO_FA_RESP_WEBAUTHN
    if channel_type == auth.TwoFactorChannel.KeeperDNA:
        return APIRequest_pb2.TWO_FA_CODE_DNA
    return APIRequest_pb2.TWO_FA_CODE_NONE


def tfa_channel_info_keeper_to_sdk(channel_info):
    # type: (APIRequest_pb2.TwoFactorChannelInfo) -> auth.TwoFactorChannelInfo
    info = auth.TwoFactorChannelInfo()
    info.channel_type = channel_keeper_to_sdk(channel_info.channelType)
    info.channel_uid = channel_info.channel_uid
    info.channel_name = channel_info.channelName
    info.phone = channel_info.phoneNumber
    info.max_expiration = duration_keeper_to_sdk(channel_info.maxExpiration)

    return info
