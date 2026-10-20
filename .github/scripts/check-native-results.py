#!/usr/bin/env python3
"""Require frozen critical cases, not merely a green or empty filtered test run."""
import argparse
import sys
import xml.etree.ElementTree as ET

# Explicit names: deleting/renaming a required fixture must update this reviewed gate.
COMMON = set("""
Server.StartupFailureNotificationIsNotReady
Server.MockUpstreamIdleShutdownWithReadableStdin
FixtureStartup.InterruptedPollRetainsSingleDeadline
FixtureStartup.RepeatedInterruptionsCannotExtendDeadline
FixtureStartup.InterruptedOrWouldBlockReadRetriesWithinDeadline
FixtureStartup.EofPartialAndFailureNotificationsAreNotReady
FixtureStartup.CancellationCannotBeLostAcrossInitialization
Server.retry_no_response
Server.fallback
Server.fallback_group
UpstreamPolicy.DatagramRetryCapMatchesOrdinaryRetryPolicy
UpstreamPolicy.ExplicitSharedBudgetStillBoundsIndependentChildren
ClientH2FlowOwner.ConcurrentSubmittersOnlyPublishUntilConsumerPumps
ClientH2FlowOwner.CancelQueuedSubmissionBeforeConsumerDoesNotEncode
ClientH2FlowOwner.FailedWakePublicationWithdrawsBothQueueReferences
Stress.Query/HTTP2
HTTP2.DownstreamDohServerToHttp2UpstreamManyConnectionsManyStreams
HTTP2.DownstreamDohServerToHttp2UpstreamSingleConnectionManyConcurrentStreams
HTTP2.UdpDownstreamToHttp2UpstreamManyConcurrentQueries
HTTP2.ScopedTlsIoPreservesBrokenPipeErrorAndSignalMask
HTTP2.ScopedTlsIoPreservesUnrelatedAndCallerOwnedSignals
ClientRule.acl
AnyOffline.UpstreamZeroWindowCancelThenUpdatePreservesCompleteSiblingDns
AnyBounded.NamedTypeDoesNotChangeAllSentinel
AnyBounded.PlainAddressProofAcceptsOnlyCompleteDirectAnswers
AnyBounded.PlainAddressProofRejectsMalformedOrUnsupportedPackets
AnyBounded.FreshMixedTtlsAndUnknownDataRemainByteExact
AnyBounded.OptFlagsAreNeverAged
AnyBounded.AgeOverflowAndTtlZeroCannotExtendCache
AnyBounded.NegativeLifetimeHonorsSoaMinimum
AnyBounded.MinimalHinfoRemainsAnExactAnyAnswer
AnyBounded.MalformedLengthsAndCompressionLoopsFail
AnyBounded.MergePreservesBinaryTxtChunksAndClearsAd
AnyBounded.PartialFailureIsExplicitAndAllFailureIsNotNoerror
AnyBounded.PositiveAndNxdomainConflictCannotBecomeSubset
AnyBounded.ConsistentCnameChainIsRetainedOnce
AnyBounded.ConflictingCnamesAndTerminalNamesFail
AnyBounded.AliasLoopAndIllegalSameOwnerDataFail
AnyBounded.CompressedMxTargetIsRelocatedSafely
AnyBounded.BothNodataRetainSoaAndAnyQuestion
AnyBounded.TruncatedChildIsNotSilentlyTreatedAsComplete
AnyBounded.QuestionOnlyTruncationIsWellFormed
AnyBounded.WrongQuestionAndEcsResponseCannotBeSynthesized
AnyBounded.OutputByteCapIsARealBound
AnyBounded.AgreeingNxdomainIsDistinctFromTransportFailure
AnyBounded.AliasDepthIsFinite
AnyBounded.AliasCycleWithoutSameOwnerDataIsRejected
AnyBounded.UnrelatedNegativeAuthorityIsRejected
AnyConfig.ModeIsExplicitAndPassthroughIsZero
AnyAddress.ParentForcedSoaCannotBypassStrictCompletion
AnyAddress.ParentLocalPolicyCannotBypassStrictCompletion
AnyAddress.ChildForcedSoaCannotMasqueradeAsGenuineNodata
AnyAddress.EcsOriginCacheCannotSupplyPlainAddressCompletion
AnyAddress.DoOriginCacheCannotSupplyPlainAddressCompletion
AnyAddress.CdAndAdOriginsCannotSupplyPlainAddressCompletion
AnyAddress.LegacyAndMetadataOnlyReplacementRevokeCacheOrigin
AnyAddress.TruncatedNativeWarmCacheCannotSupplyAddressCompletion
AnyAddress.AdditionalOnlyNativeWarmCacheCannotSupplyAddressCompletion
AnyAddress.NormalSpeedSelectionPreservesBothFamiliesAndPolicyTtls
AnyAddress.DoAndCdFailClosedWithoutAnyProbe
AnyAddress.OrdinaryNegativeCacheIsRevalidatedWhileFreshPositiveCacheIsReused
AnyAddress.LastTcpWaiterCancellationReleasesNativeChildrenWithoutPoisoningRetry
AnyAddress.GroupsInheritAddressAndCanExplicitlyOverridePassthrough
AnyConfig.AddressIsExplicitAndPreservesLegacyOptionsForModeSwitch
AnyAddress.DualFamilyOverUdpAndTcpNeverProbesHinfoCapableUpstream
AnyAddress.FixedFamiliesAndConcurrencyIgnoreLegacyAggregateSelection
AnyAddress.IPv4OnlyRequiresGenuineIpv6Nodata
AnyAddress.IPv6OnlyRequiresGenuineIpv4Nodata
AnyAddress.TimeoutCannotBecomeSingleStackEvenWithPartialYes
AnyAddress.RefusedAndServfailCannotBecomeSingleStack
AnyAddress.EmptyNoerrorAndUnrelatedSoaAreNotProofOfNodata
AnyAddress.CoherentBothNodataRetainsGenuineSoa
AnyAddress.CoherentBothNxdomainRetainsGenuineSoa
AnyAddress.ContradictoryNxdomainCannotBecomePositiveOrNodata
AnyAddress.InconsistentNegativeSoaFailsStrictly
AnyAddress.MatchingCnameChainsAreEmittedOnceWithBothAddresses
AnyAddress.ConflictingCnameTargetsCannotBecomePartialAnswers
AnyAddress.DifferentCnamePathsToSameTerminalStillConflict
AnyAddress.MatchingCnameWithOppositeFamilyNodataReturnsOneAddress
AnyAddress.FreshOrdinaryAAndAaaaCacheEntriesAvoidAllAddressUpstreamSends
AnyAddress.OneFreshOrdinaryFamilyCacheOnlyFetchesTheMissingFamily
AnyAddress.OneSendBudgetFailsRatherThanExposingOneSuccessfulFamily
AnyAddress.CacheZeroCoalescesAdmittedTcpWaitersThenFetchesAgain
AnyConfig.TypeListIsRequiredFiniteAndHasNoMetaTypes
AnyConfig.NumericBoundsRejectRatherThanClamp
AnyConfig.PartialRequiresYesOrNo
AnyConfig.AggregateModeWithoutTypeListFailsFinalValidation
AnyOffline.DefaultPassthroughDoesNotExpandRefused
AnyOffline.DefaultDuplicateBurstFallsBackToNativeWhenCoordinatorFull
AnyOffline.DefaultUniqueBurstFallsBackToNativeWhenCoordinatorFull
AnyOffline.MinimalSuccessStopsAndExactCacheAvoidsSecondProbe
AnyOffline.RefusedExpandsExactlyConfiguredTypesAndCaches
AnyOffline.CacheSizeZeroRepeatsPassthroughUpstreamLookup
AnyOffline.CacheSizeZeroRepeatsAggregateProbeAndChildren
AnyOffline.OneSendBudgetIncludesProbeAndCannotStartTypedWireWork
AnyOffline.DoAndCdBypassNewAggregationAndSharing
AnyOffline.OrdinaryAQueryHasNoAnyExpansion
AnyOffline.DuplicateCallersShareOneBoundedOperation
AnyOffline.UdpTcAndTcpRetryUseTheSameCompleteSnapshot
AnyOffline.CancelledTcpWaiterDoesNotCancelSharedUdpWork
AnyOffline.LastWaiterCancellationDoesNotStartTypedFallback
AnyOffline.EcsRequestBypassesAggregateAndSharedCache
AnyOffline.SameQuestionOnDifferentRoutesCannotShareCachedAnswer
AnyOffline.SlowProbeConsumesTheTypedFallbackDeadline
AnyOffline.OneClientCannotOwnAllCoordinatorSlots
AnyOffline.DefaultFailureFirstCannotMaskHealthySibling
AnyOffline.DefaultAllFailuresRetainTheFirstBoundedResponse
AnyOffline.DefaultLastWaiterCancellationStopsDeferredAdmission
AnyOffline.DefaultLastWaiterCancellationStopsRetry
AnyOffline.DefaultFailureWaitsForDeferredHealthySibling
AnyOffline.DefaultRefusalCannotMaskMinimalHinfoSibling
Bind.tls
Bind.cert_explicit_path_without_auto_generate_skips_generation
BootStrap.bootstrap
ClientH2FlowOwner.WindowUpdateAfterCancelDiscardsBodyAndPreservesLiveSibling
ClientH2FlowOwner.WindowUpdateAfterQueryPruneCannotResurrectBody
ClientH2FlowOwner.WindowUpdateAfterDeadlineCannotEmitExpiredBody
ClientH2PartialOwner.CancelWithEncodedPartialHeadersRequiresConnectionClose
ClientHttp2RetryReentrancy.ReentrantCloseSocketTearsDownPinnedStreamAndSsl
ClientHttp2RetryReentrancy.ConcurrentStreamPinnedWhileSiblingStreamTriggersRetryClose
AnyOffline.Http2ResetOnlyCancelsItsWaiter
AnyOffline.LastHttp2ResetCancelsFallbackButKeepsConnectionUsable
UpstreamPolicy.BufferedAdmissionDoesNotSpendParentSendBudget
UpstreamPolicy.ZeroRateIsDisabledAndPerDestinationAttemptsAreBounded
UpstreamPolicy.SharedRateDoesNotChargeUnrelatedEndpoint
UpstreamPolicy.CooldownIsScopedAndDoesNotBecomeProhibition
UpstreamPolicy.CancellationPreventsBufferedSend
UpstreamPolicy.ConflictingQuotaGroupRejected
HpackRFC7541.AppendixCEncodedAuthority
HpackRFC7541.RejectEOSAndOverlongOrNonEOSPadding
Http1OwnershipFraming.ZeroLengthDoesNotConsumeNextResponse
HpackRFC7541.EveryPrintableOctetUsesAppendixBCode
UpstreamPolicy.CancellationAlsoStopsPartialWriteContinuation
UpstreamPolicy.UnprogressedWriteMustRecheckSharedRate
UpstreamPolicy.TcpProductionQueueCancelBeforeHandshakeWritesNoBytes
UpstreamPolicy.TcpProductionQueueWritesOneFramedAttemptAfterHandshake
UpstreamPolicy.RetryAfterDateFormsAndInvalidCalendar
UpstreamPolicy.RetainedFailureDoesNotResendAlreadyRepliedEndpoint
UpstreamPolicy.Http1ProductionWriteOwnerBecomesCancellationTombstone
""".split())
QUIC = set("""
ClientHTTP3.incomplete_response_keeps_stream_pending
ClientHTTP3.split_data_frame_with_content_length_keeps_stream_pending
ClientHTTP3.header_only_with_content_length_keeps_stream_pending
ClientHTTP3.header_only_without_content_length_keeps_stream_pending
ClientHTTP3.response_without_content_length_accepts_complete_dns_message
ClientHTTP3.response_without_content_length_incomplete_dns_body_waits_for_more_data
ClientHTTP3.fragmented_response_without_content_length_accepts_delayed_final_data
ClientHTTP3.quic_poll_reference_keeps_stream_alive_until_poll_done
ClientHTTP3.RequestProtocolErrorsSelectConnectionApplicationCode
ClientHTTP3.FragmentedInformationalThenFinalHeadersRemainPendingUntilFin
Http3Control.SettingsAtEverySplitAndLegalNonminimalVarints
Http3Control.MissingRepeatedAndDuplicateUnknownSettingsFail
Http3Control.UnknownFramesSkipIncrementally
Http3Control.DuplicateCriticalStreamsAndPushRejected
Http3Control.ZeroCapacityEncoderAndLegalDecoderCancellation
Http3Control.GoawayStopsNewAndClassifiesAlreadyStarted
Http3RequestFraming.RejectSettingsOnRequestStream
Http3RequestFraming.StaticOnlyQpackAllowsPositiveMultibyteBase
Http3RequestFraming.IncompleteVarintIsNotReadPastInput
StrictPeer.EmitsSettingsWithoutWaitingForPeerSettings
StrictPeer.GoawayStopsNewRequestsAndCriticalFinFails
StrictPeer.IdleLocalControlStopSendingSelectsClosedCriticalStream
StrictPeer.ProductionQueueCancellationBeforeWriteSpendsNoSendBudget
StrictPeer.AdmissionRechecksTerminalQueryAfterStreamAllocation
StrictPeer.ProductionQueuedGoawayRetiresRequestWithoutClosingConnection
StrictPeer.ProductionHttp3PayloadWithoutFinThenResetIsNotSuccess
StrictPeer.ProductionDoqFramingDoesNotTreatResetAsFin
StrictPeer.RequestSettingsErrorReachesPeerAsApplicationConnectionClose
""".split())


def validate(root, profile):
    cases = {}
    errors = []
    for suite in root.iter('testsuite'):
        for case in suite.findall('testcase'):
            name = suite.get('name', '') + '.' + case.get('name', '')
            if name in cases:
                errors.append('duplicate: ' + name)
            cases[name] = case
            if case.find('failure') is not None or case.find('error') is not None:
                errors.append('failed: ' + name)
            if case.find('skipped') is not None or case.get('status') == 'notrun':
                print('SKIP:', name)
    required = COMMON | (QUIC if profile == 'quic' else set())
    for name in sorted(required):
        case = cases.get(name)
        if case is None:
            errors.append('missing required case: ' + name)
        elif case.find('skipped') is not None or case.get('status') != 'run' or case.get('result') != 'completed':
            errors.append('required case did not complete: ' + name)
    if not cases:
        errors.append('no test cases')
    # Also catch framework/global setup failures reflected only in aggregate counters.
    for node in root.iter():
        if node.tag in ('testsuites', 'testsuite'):
            for attr in ('failures', 'errors'):
                if int(node.get(attr, '0')):
                    errors.append(f'{node.tag} reports {attr}')
    if errors:
        raise ValueError('\n'.join(errors))
    print(f'Accepted {len(cases)} reported cases; {len(required)} critical cases completed ({profile}).')


def self_test():
    def fixture():
        root = ET.Element('testsuites')
        for full in sorted(COMMON | QUIC):
            suite, name = full.split('.', 1)
            node = ET.SubElement(root, 'testsuite', name=suite)
            ET.SubElement(node, 'testcase', name=name, status='run', result='completed')
        return root
    for profile in ('system', 'quic'):
        validate(fixture(), profile)
    for kind in ('missing', 'skip', 'notrun', 'failure', 'aggregate', 'duplicate', 'empty'):
        root = fixture()
        case = root[0][0]
        if kind == 'missing': root.remove(root[0])
        elif kind == 'skip': ET.SubElement(case, 'skipped')
        elif kind == 'notrun': case.set('status', 'notrun')
        elif kind == 'failure': ET.SubElement(case, 'failure')
        elif kind == 'aggregate': root.set('failures', '1')
        elif kind == 'duplicate': root.append(root[0])
        elif kind == 'empty': root.clear()
        try:
            validate(root, 'quic')
        except ValueError:
            continue
        raise AssertionError('negative gate fixture incorrectly passed: ' + kind)
    print('Result-gate synthetic positive/negative checks passed; no native tests executed.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--profile', choices=('system', 'quic'))
    parser.add_argument('xml', nargs='?')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.profile or not args.xml:
        parser.error('--profile and XML path required')
    try:
        validate(ET.parse(args.xml).getroot(), args.profile)
    except (OSError, ET.ParseError, ValueError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
