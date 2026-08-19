import os
import unittest

from keepersdk.errors import KeeperError
from keepersdk.helpers.workflow import WorkflowError, WorkflowFormatter
from keepersdk.proto import workflow_pb2


class WorkflowFormatterTestCase(unittest.TestCase):
    def test_parse_duration(self):
        self.assertEqual(WorkflowFormatter.parse_duration('1d'), 86_400_000)
        self.assertEqual(WorkflowFormatter.parse_duration('2h'), 7_200_000)
        self.assertEqual(WorkflowFormatter.parse_duration('30m'), 1_800_000)
        self.assertEqual(WorkflowFormatter.parse_duration('15'), 15 * 60_000)

    def test_parse_duration_invalid(self):
        with self.assertRaises(WorkflowError):
            WorkflowFormatter.parse_duration('0h')
        with self.assertRaises(WorkflowError):
            WorkflowFormatter.parse_duration('abc')
        self.assertIsInstance(WorkflowError('x'), KeeperError)

    def test_format_duration(self):
        self.assertEqual(WorkflowFormatter.format_duration(86_400_000), '1 day')
        self.assertEqual(WorkflowFormatter.format_duration(172_800_000), '2 days')
        self.assertEqual(WorkflowFormatter.format_duration(3_600_000), '1 hour')
        self.assertEqual(WorkflowFormatter.format_duration(60_000), '1 minute')
        self.assertEqual(WorkflowFormatter.format_duration(5_000), '5 seconds')

    def test_format_stage(self):
        self.assertEqual(
            WorkflowFormatter.format_stage(workflow_pb2.WS_STARTED), 'Started')
        self.assertEqual(
            WorkflowFormatter.format_stage(workflow_pb2.WS_WAITING), 'Waiting')

    def test_format_conditions(self):
        text = WorkflowFormatter.format_conditions(
            [workflow_pb2.AC_APPROVAL, workflow_pb2.AC_MFA])
        self.assertEqual(text, 'Approval Required, MFA Required')

    def test_build_temporal_filter_days(self):
        os.environ['TZ'] = 'America/New_York'
        temporal = WorkflowFormatter.build_temporal_filter('mon,fri', None)
        self.assertIsNotNone(temporal)
        self.assertEqual(list(temporal.allowedDays), [workflow_pb2.MONDAY, workflow_pb2.FRIDAY])
        self.assertEqual(temporal.timeZone, 'America/New_York')

    def test_build_temporal_filter_time_range(self):
        os.environ['TZ'] = 'Asia/Kolkata'
        temporal = WorkflowFormatter.build_temporal_filter(None, '09:00-17:30')
        self.assertEqual(len(temporal.timeRanges), 1)
        self.assertEqual(temporal.timeRanges[0].startTime, 900)
        self.assertEqual(temporal.timeRanges[0].endTime, 1730)

    def test_build_temporal_filter_invalid_day(self):
        os.environ['TZ'] = 'UTC'
        with self.assertRaises(WorkflowError):
            WorkflowFormatter.build_temporal_filter('funday', None)

    def test_build_temporal_filter_invalid_time_range(self):
        os.environ['TZ'] = 'UTC'
        with self.assertRaises(WorkflowError):
            WorkflowFormatter.build_temporal_filter(None, '17:00-09:00')

    def test_build_temporal_filter_invalid_timezone(self):
        os.environ['TZ'] = 'garbage/value'
        with self.assertRaises(WorkflowError):
            WorkflowFormatter.build_temporal_filter(None, '09:00-17:00')

    def test_format_temporal_filter(self):
        temporal = workflow_pb2.TemporalAccessFilter()
        temporal.allowedDays.append(workflow_pb2.MONDAY)
        tr = temporal.timeRanges.add()
        tr.startTime = 900
        tr.endTime = 1700
        temporal.timeZone = 'UTC'
        formatted = WorkflowFormatter.format_temporal_filter(temporal)
        self.assertEqual(formatted['allowed_days'], ['Monday'])
        self.assertEqual(formatted['time_ranges'], ['09:00-17:00'])
        self.assertEqual(formatted['timezone'], 'UTC')


if __name__ == '__main__':
    unittest.main()
