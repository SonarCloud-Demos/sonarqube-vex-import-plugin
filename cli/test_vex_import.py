"""Unit tests for cli/vex-import.py's status mapping and assessment.

Run: python3 -m unittest discover -s cli -p 'test_*.py'
No network: detected risks and changelogs are passed in as plain data.
"""
import importlib.util
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location('vex_import', os.path.join(_HERE, 'vex-import.py'))
vex_import = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vex_import)

CVE = 'CVE-2024-1111'
PURL = 'pkg:npm/express@4.19.2'


def risk(status='OPEN', transitions=('ACCEPT', 'CONFIRM', 'SAFE')):
    return {
        'issue_release_key': 'key-1',
        'vulnerability_id': CVE,
        'package_url': PURL,
        'status': status,
        'transitions': list(transitions),
    }


def candidate(analysis, vex_reference_date=None):
    return {
        'vulnerability_id': CVE,
        'package_url': PURL,
        'analysis': analysis,
        'vex_reference_date': vex_reference_date,
    }


def no_history(_key):
    return []


class MapAnalysisTest(unittest.TestCase):
    def test_default_mapping_matches_v0_1_0(self):
        cases = [
            ({'state': 'not_affected'}, 'SAFE'),
            ({'state': 'false_positive'}, 'SAFE'),
            ({'state': 'resolved'}, 'FIXED'),
            ({'state': 'resolved_with_pedigree'}, 'FIXED'),
            ({'state': 'exploitable', 'response': ['will_not_fix']}, 'ACCEPT'),
            ({'state': 'exploitable', 'response': ['update']}, 'CONFIRM'),
            ({'state': 'exploitable'}, 'CONFIRM'),
        ]
        for analysis, target in cases:
            with self.subTest(analysis=analysis):
                self.assertEqual(vex_import.map_analysis_to_transition(analysis)[:2], (False, target))

    def test_default_reasons_are_unchanged(self):
        self.assertEqual(vex_import.map_analysis_to_transition(None), (True, 'VEX entry has no analysis.state', None))
        self.assertEqual(vex_import.map_analysis_to_transition({}), (True, 'VEX entry has no analysis.state', None))
        self.assertEqual(
            vex_import.map_analysis_to_transition({'state': 'in_triage'}),
            (True, "VEX analysis.state 'in_triage' is not actionable", None),
        )
        self.assertEqual(
            vex_import.map_analysis_to_transition({'state': 'made_up'}),
            (True, "VEX analysis.state 'made_up' is not actionable", None),
        )

    def test_undecided_open(self):
        mapping = vex_import.build_mapping(undecided='open')
        self.assertEqual(
            vex_import.map_analysis_to_transition({'state': 'in_triage'}, mapping),
            (False, 'OPEN', 'VEX import: state=in_triage'),
        )
        self.assertEqual(
            vex_import.map_analysis_to_transition({'state': 'made_up'}, mapping),
            (False, 'OPEN', 'VEX import: state=made_up'),
        )
        self.assertEqual(
            vex_import.map_analysis_to_transition({}, mapping),
            (False, 'OPEN', 'VEX import: no analysis.state'),
        )
        self.assertEqual(
            vex_import.map_analysis_to_transition({'state': 'in_triage', 'detail': ' Vendor investigating '}, mapping)[2],
            'Vendor investigating',
        )

    def test_decided_state_mapped_to_skip_has_distinct_reason(self):
        mapping = vex_import.build_mapping(overrides=['resolved=skip'])
        self.assertEqual(
            vex_import.map_analysis_to_transition({'state': 'resolved'}, mapping),
            (True, "VEX analysis.state 'resolved' is mapped to Skip", None),
        )


class BuildMappingTest(unittest.TestCase):
    def test_default(self):
        self.assertEqual(vex_import.build_mapping(), vex_import.DEFAULT_MAPPING)
        self.assertEqual(vex_import.describe_mapping(vex_import.build_mapping()), 'default')

    def test_map_applies_after_undecided(self):
        mapping = vex_import.build_mapping(undecided='open', overrides=['missing=skip', 'false_positive=CONFIRM'])
        self.assertEqual(mapping['in_triage'], 'OPEN')
        self.assertEqual(mapping['unrecognized'], 'OPEN')
        self.assertEqual(mapping['missing'], 'SKIP')
        self.assertEqual(mapping['false_positive'], 'CONFIRM')
        self.assertEqual(
            vex_import.describe_mapping(mapping),
            'false_positive -> CONFIRM, in_triage -> OPEN, unrecognized -> OPEN',
        )

    def test_rejects_bad_input(self):
        for overrides in (['in_triage'], ['bogus=open'], ['in_triage=reopen']):
            with self.subTest(overrides=overrides), self.assertRaises(vex_import.UsageError):
                vex_import.build_mapping(overrides=overrides)
        with self.assertRaises(vex_import.UsageError):
            vex_import.build_mapping(undecided='maybe')

    def test_does_not_mutate_default(self):
        vex_import.build_mapping(undecided='open')
        self.assertEqual(vex_import.DEFAULT_MAPPING['in_triage'], 'SKIP')


class AssessImportTest(unittest.TestCase):
    def assess(self, analysis, detected, mapping=None, fetch_changelog=no_history, vex_reference_date=None):
        return vex_import.assess_import([candidate(analysis, vex_reference_date)], [], detected, fetch_changelog, mapping)

    def test_default_blocks_in_triage(self):
        importable, blocked, conflicts, unchanged = self.assess({'state': 'in_triage'}, [risk()])
        self.assertEqual((importable, conflicts, unchanged), ([], [], []))
        self.assertEqual(blocked[0]['reason'], "VEX analysis.state 'in_triage' is not actionable")

    def test_open_on_open_risk_is_unchanged(self):
        calls = []
        importable, blocked, conflicts, unchanged = self.assess(
            {'state': 'in_triage'}, [risk('OPEN')], vex_import.build_mapping(undecided='open'),
            fetch_changelog=lambda key: calls.append(key) or [],
        )
        self.assertEqual((importable, blocked, conflicts), ([], [], []))
        self.assertEqual(unchanged, [{'vulnerability_id': CVE, 'package_url': PURL, 'current_status': 'OPEN'}])
        self.assertEqual(calls, [], 'no history lookup needed when nothing changes')

    def test_open_on_triaged_risk_reopens(self):
        for status in ('CONFIRM', 'ACCEPT', 'SAFE'):
            with self.subTest(status=status):
                importable, blocked, _, _ = self.assess(
                    {'state': 'in_triage', 'detail': 'Vendor investigating'},
                    [risk(status, ('REOPEN',))],
                    vex_import.build_mapping(undecided='open'),
                )
                self.assertEqual(blocked, [])
                self.assertEqual(importable[0]['transition_key'], 'REOPEN')
                self.assertEqual(importable[0]['current_status'], status)
                self.assertEqual(importable[0]['comment'], 'Vendor investigating')

    def test_reopen_not_offered_is_blocked(self):
        importable, blocked, _, _ = self.assess(
            {'state': 'in_triage'}, [risk('FIXED', ())], vex_import.build_mapping(undecided='open'),
        )
        self.assertEqual(importable, [])
        self.assertEqual(blocked[0]['reason'], 'transition REOPEN is not valid from current status FIXED for this risk')

    def test_reopen_goes_through_conflict_guard(self):
        history = [{
            'createdAt': '2026-02-01T00:00:00Z',
            'user': {'login': 'someone'},
            'changeData': [{'fieldName': 'status', 'oldValue': 'OPEN', 'newValue': 'CONFIRM'}],
        }]
        importable, _, conflicts, _ = self.assess(
            {'state': 'in_triage'}, [risk('CONFIRM', ('REOPEN',))], vex_import.build_mapping(undecided='open'),
            fetch_changelog=lambda key: history, vex_reference_date='2026-01-01T00:00:00Z',
        )
        self.assertEqual(importable, [])
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]['item']['transition_key'], 'REOPEN')


if __name__ == '__main__':
    unittest.main()
