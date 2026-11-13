#!/usr/bin/env python3
"""Require frozen critical cases, not merely a green or empty filtered test run."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

# Explicit names: deleting/renaming a required fixture must update this reviewed gate.
COMMON = set("""
ConfServer.scheme_and_keyword_type
Http2Cancellation.CompletedServerRequestStillHonorsPeerCancellation
Cache.InvalidPersistedRecordDoesNotDiscardValidNeighbors
Cache.BrokenRecordFramingStopsBeforeUntrustedPayload
Cache.ValidLargeTtlSurvivesPrefetchPersistenceAndOfflineReload
Cache.FuturePersistedTimesAreDiscardedWithoutRenewingTtl
Cache.ValidPersistedCounterBoundsDoNotResetRecordTimes
Cache.PersistedExpiryHonorsServeExpiredWindow
Cache.TtlConsumersDoNotOverflowAtRepresentableLimits
ThreadStartup.ClientThreadFailureCanRetryWithoutLeakingGroups
ThreadStartup.ClientEpollFailureCanRetry
ThreadStartup.ClientWakeupFailureJoinsWorkerAndCanRetry
LibConf.DefaultTlsCertificatesStayBesideTheTopConfiguration
HTTP2.ConnectedDohRequestsPreserveFastReplyBeforePublication
LIBHTTP2.PeerTableGrowthStaysWithinLocalEncoderLimit
Ping.Ipv6ReadinessCallerRetainsItsStopReferenceAfterEarlyEnd
ClientH2FlowOwner.ConcurrentEnqueueRetainsKernelWriteInterest
ClientH2FlowOwner.BlockedWriteOwnerDoesNotSpinOnWritableSocket
Http2Cancellation.AbortDiscardsUnscheduledBodyAndReleasesCapacity
Http2Cancellation.NormalCloseStillFlushesAfterWindowUpdate
Http2Cancellation.ResetIsDistinctFromFinishedBodyAndSurvivesContextTeardown
Http2Cancellation.IdleAbortDoesNotResetAnUnopenedStream
Http2Cancellation.ReceivedResetDoesNotGenerateAnotherReset
Http2Cancellation.CompletedResponseSurvivesFollowingNoErrorReset
Http2Cancellation.CompletedResponseSurvivesFollowingGoaway
ThreadStartup.PingThreadFailureUsesDefaultAttributesAndCanRetry

EgressContract.LeaseParsingFitsSmallStackBelowNestedDiscoveryFrames
EgressContract.RepeatedAdmissionReusesIoctlSocketWithoutCachingInterfaceIdentity
EgressContract.ReusedIoctlDetectsLinkRemovalAndRecreationBeforeLeaseRefresh
UpstreamServiceDiscovery.WanBootstrapRefreshPreservesEndpointStateAndWorkerStack
EgressContract.UnchangedRenewalAndOneWanReplacementPreserveOtherWanGenerationAndSocket
EgressContract.MdnsAndLanBindingAreNotImplicitContractAdopters
EgressContract.RevokedQuicEventsAndTlsShutdownDoNotTouchTransportObjects
EgressContract.ReplacingInterfaceNameBetweenLookupAndBindRejectsBeforeConnect
UpstreamServiceState.EgressRevocationBlocksFirstWireAndAlreadyStartedContinuation
EgressContract.ExpiryRevocationBootPermissionAndMalformedInputFailClosed
EgressContract.BoundTcpAndUdpBothFamiliesPrepareBeforeIoAndRejectConflictingMarks
EgressContract.UnboundSocketsKeepTheirConfiguredPolicyAndFamilyAdmissionIsExplicit
EgressContract.SameInterfaceSameAddressNewSessionRetiresSocketIdentity
EgressContract.MaximumInventoryIsBoundedAndOneExtraRowRevokesAdmission
AnyAddress.ExpiredEnabledKeepsNativeShortReplyPolicyForBothFamilies
LIBHTTP2.DisconnectStopsAllBioCalls
TimerWheel.FiresBeforeStop
TimerWheel.StopIsPromptAndNoTimerFiresAfterStop
Shutdown.ExitWithPendingQueriesAndExpiringCache
ClientH2Maintenance.KeepaliveIoDoesNotHoldEndpointLock
ClientH2Maintenance.ReentrantCloseWaitsForMaintenanceToReleaseTransport
CachePolicy.ServeExpiredNoKeepsFreshAnswerTTL
CachePolicy.ServeExpiredNoDoesNotServeExpiredPacket
DomainRuleLayout.HeaderStaysPointerAligned
DomainRuleInheritance.ChildFlagValueChangePreservesParent
DomainRuleInheritance.ChildChangeOfSharedEntryPreservesParent
FastestResponse.first_pool_speed_checked
FastestResponse.internal_query_result_has_ip
InProcessServer.ForkedServerKeepsRunning
InProcessServer.ForkedServerKeepsIPv6SpeedCheck
QtypeSOA.BlockedStatusOnlyForBlockingSOA
NftSet.ReAddRefreshesTimeout
NftSet.ConcurrentAddsKeepRepliesAssociated
IpSet.ConcurrentFirstUseCreatesOneSocket
NftSet.LastByteOfOctetCanBeAdded
NftSet.ExpiryLeavesNoStrayRange
NftSet.StaticRangeIsKept
NftSet.TimeoutCoversServeExpired
UpstreamCompleted.LateSrvPoolKeepsCompletionWithoutRetryOrEndpointPenalty
UpstreamCompleted.LateSrvOrdinaryKeepsCompletionWithoutRetry
UpstreamCompleted.LateUsableAddressStillUsesNativeProcessing
UpstreamCompleted.LateActualServfailRemainsVisible
UpstreamServiceState.OneLimitedNodeDoesNotCoolHealthyPeerAndAllBlockedUseEarliestThaw
UpstreamServiceState.NodeIsolationCannotRefillOrBypassSharedServiceRate
UpstreamServiceState.TransportFailureWaitUsesFixedConfiguredNodeCooldownWithoutGrowth
UpstreamEndpointDiagnostics.AcceptedNegativeResponseClosesExactlyOnceAndPreservesNonPoolRouting
UpstreamEndpointDiagnostics.SentRaceUnsentRateWaitAndLocalCancelRemainDistinct
UpstreamEndpointDiagnostics.RejectedOwnResultHasProvenanceAndLastEventRatherThanAnotherWinner
UpstreamEndpointDiagnostics.PositiveWriteRacingTerminalIsSentAndRetriesRemainOneLogicalQuery
UpstreamEndpointDiagnostics.HttpCountersAreIndependentOfBoundedEventWindowAndCaptureWallTime
UpstreamEndpointDiagnostics.DeadlineAndIoFailureAreRealEvidenceWithoutGeneratingProbeTraffic
UpstreamEndpointDiagnostics.IdentityIgnoresUnusedUnionBytesAndLoadDiscriminatorButIncludesEgress
UpstreamEndpointDiagnostics.ExistingCopiedApisResolveOrdinaryEndpointAndKeepLegacySnapshotCounters
UpstreamEndpointDiagnostics.RealOrdinaryUdpRecordsPositiveSoaNegativeAndNxDomainThroughExistingApis
MockServer.InterruptedPollDoesNotDelayReply
ClientH2FlowOwner.PeerCloseWithoutOrphanMustReachEOF
ClientH2FlowOwner.LateCancelledResponseAndPeerCloseMustReachEOF
ClientH2FlowOwner.LateCancelledResponseDoesNotRetainReadinessOrBreakSibling
UpstreamServiceTransport.LateCancelledH2ResponseDoesNotSpinClientLoop
UpstreamPolicy.RecoveryPreservesExplicitRateAndFixedCooldown
UpstreamServiceState.DiagnosticResultProvenanceDoesNotCallOwnRejectedResultAnotherWinner
UpstreamServiceState.FixedCooldownDefaultsAndDoesNotGrowOrFollowRetryAfter
UpstreamServiceState.DiagnosticDimensionsDistinguishOtherWinnerCoolingAndRejectedReply
UpstreamServiceState.DiagnosticsRecordLastObservedErrorSeparatelyFromTerminalContext
UpstreamPoolConfig.FixedCooldownMillisecondsDefaultBoundsAndStrictGrammar
UpstreamDiagnostics.LoopSeparatesEmptyZeroWaitsReadinessWakeupsAndCpuWindow
UpstreamServiceTransport.RealH2ConfiguredCooldownOverridesLongRetryAfter
UpstreamServiceState.SnapshotFreshnessHasNoInfiniteIntegerSentinel
UpstreamServiceState.CancelBetweenObservationPublicationAndRegistrationIsDeferred
UpstreamServiceDiscovery.FourSilentBootstrapMembersDoNotStarveFifth
UpstreamServiceDiscovery.FreshOneSendBootstrapQueriesAdvanceAcrossAllMembers
UpstreamServiceState.NoProgressWaitsWithoutEventfdSelfFeedOrDeadlineExtension
UpstreamServiceState.ExhaustedBudgetSettlesWithoutRetryWakeLoop
UpstreamServiceState.DatagramBackpressureAbortsOwnerButWaitsWithoutSelfFeed
UpstreamServiceState.EpollBatchPinsLaterEndpointAcrossEarlierCallbackRetirement
UpstreamServiceDiscovery.GlobalServerAndExplicitEcsCannotLeakIntoBootstrap
UpstreamServiceDiscovery.NumericBootstrapCannotMaskPendingAliasToSelf
UpstreamServiceDiscovery.CanonicalCapIgnoresRrOrderAndWithdraws
UpstreamServiceDiscovery.CanonicalCapIgnoresReverseRrOrderAndWithdraws
UpstreamServiceDiscovery.WildcardListenerActualSocketRejectsSelf
UpstreamServiceDiscovery.LocalhostListenerActualSocketRejectsSelf
UpstreamServiceDiscovery.MappedListenerActualSocketRejectsSelf
UpstreamServiceDiscovery.SameAddressPortDifferentTransportRemainsUsable
UpstreamServiceDiscovery.SilentFirstBootstrapRotatesWithoutDefaultOrFallback
UpstreamServiceTransport.RealTlsSingleWanReusesOneHealthyAddress
UpstreamServiceTransport.RealH2SingleWan429WaitsWithoutSwitchingIpQuota
UpstreamServiceTransport.RealTlsNodataCompletesServiceWithoutDuplicateAttempt
UpstreamServiceTransport.RealH2Nodata20CompletesServiceWithoutDuplicateAttempt
UpstreamServiceTransport.RealH2Nodata40CompletesServiceWithoutDuplicateAttempt
UpstreamServiceState.CursorCommitsOnlyPositiveRequestWrites
UpstreamServiceState.WantWriteRetainsOneTurnAndAbortedOwnerCannotResume
UpstreamServiceState.PositiveWriteWinningCancellationCannotBecomeSkip
UpstreamServiceState.ReadyEndpointFailureIsolationAndNoCatchupDebt
UpstreamServiceState.ConfigurablePhysicalCapIncludesConnectingAndRevokedMembers
UpstreamServiceState.UnspecifiedPhysicalCapTracksActualMembersNotTwo
UpstreamServiceState.SharedQuotaNeverMultipliesWithDifferentServicesOrIPs
UpstreamServiceState.ParentBudgetAndDeadlineRemainAuthoritativeAcrossIPs
UpstreamRoundRobin.MixedGroupLegacyFirstConnectionIsNotFalselyProhibited
UpstreamServiceState.NewEpochRejectsOldUnsentOwnerAndAllowsExactlyOneProbe
UpstreamServiceState.OldInflightReplyCannotClearNewEpochAndCanceledProbeReleasesOnlyItsLease
UpstreamServiceState.ConcurrentSelectionsReserveExactlyOneUncommittedTurn
UpstreamServiceState.ServiceConcurrencyAndOneActiveAttemptDoNotMultiplyPerIP
UpstreamServiceState.ResponseBeforeCommitFinalizesOnceWithConsistentOutcomes
UpstreamServiceState.FailedPhysicalCreationReleasesItsReservation
UpstreamServiceState.CancellationDuringSelectionCannotReleaseAnotherTurn
UpstreamServiceState.CancelBeforePositiveWriteSkipsButCancelAfterPositivePendingCountsFailure
UpstreamServiceState.FiveBackendActualSendOrderIsStableAndBalanced
UpstreamServiceState.StaleAttemptGenerationCannotWriteOrCommitNewTurn
UpstreamServiceState.ExpiredAndRevokedMembersStopNewAdmissionImmediately
UpstreamPoolConfig.PathPolicyDefaultsAndExplicitZeroRemainDistinct
UpstreamPoolConfig.PathPolicyRejectsInvalidUnitsBoundsAndLegacyUse
UpstreamPaths.ForcedFamilyFiltersTransportWithoutChangingDiscovery
UpstreamPaths.MissingBoundInterfaceDoesNotBecomeReachable
UpstreamPaths.SingleStackRecoversAndWithdrawsOnActualRouteEvents
UpstreamPaths.EventContextRingKeepsExactSequenceTimestampAndDnsEvidence
UpstreamDiagnostics.EvidenceRingIsBoundedOrderedAndSeparateFromQueryOutcomes
UpstreamServiceTransport.H2SlowValidResponseDoesNotTriggerLegacy500msRetry
UpstreamServiceTransport.DualFamilyStaggerFallsBackBeforeStalledTlsTimeout
UpstreamServiceTransport.LegacySingleConnectionCapDoesNotDisableWanFamilyFallback
UpstreamServiceTransport.H2IdlePingAcknowledgedWithoutDnsBudgetAndReusesSocket
ClientH2FlowOwner.PingAckUsesControlFrameWithoutDnsStreamOrRequestBudget
ClientH2FlowOwner.GracefulGoawayStopsAdmissionAndDoesNotBecomeProtocolError
UpstreamServiceTransport.ForcedIPv4StillCarriesValidAaaaNodata
UpstreamServiceTransport.ForcedIPv6UsesActualIpv6TlsSocket
UpstreamServiceTransport.DualFamily20ReusesHealthyFamilyAndSharesQps
UpstreamServiceTransport.DualFamily40ReusesHealthyFamilyAndSharesQps
UpstreamServiceTransport.FourCandidatesOneHealthyConnectionAt20Qps
UpstreamServiceTransport.FourCandidatesOneHealthyConnectionAt40Qps
UpstreamServiceState.ServiceDeadlineRecordsWholeAgeWithoutPenalizingEndpoint
UpstreamDiagnostics.OtherHttpStatusRetainsActualCodeWithoutInventingSocketFailure
UpstreamPoolConfig.ExplicitOptInRetainsAuthorityAndActualList
UpstreamPoolConfig.CanonicalDedupPreservesFirstOccurrenceOrder
UpstreamPoolConfig.ConfiguredCapDoesNotDiscardStaticCandidates
UpstreamPoolConfig.StrictListErrorsAndForbiddenAddresses
UpstreamPoolConfig.RejectsInvalidCapsAndConflictingModes
UpstreamPoolConfig.OffModeDoesNotEnableOrAcceptLists
UpstreamPoolConfig.QuotaGroupSharesRateButNotPoolPhysicalCap
UpstreamPoolConfig.MalformedNewOptionsCannotSilentlyBecomeDefaults
UpstreamPoolConfig.ExplicitListCanReachSafeBoundWithoutFixedTwoOrFour
UpstreamPoolConfig.LegacyRrNormalizesIntoExactlyOneServiceWithoutInventingRate
UpstreamPoolConfig.LegacyRrMismatchFailsBeforeAnyMutation
UpstreamPoolConfig.LegacyEndpointConcurrencyRequiresExplicitMigration
UpstreamPoolConfig.LegacyDifferentGroupIntersectionsCannotBeCollapsed
UpstreamPoolConfig.LegacyIdenticalGroupSetsKeepPointersAndQuotaValues
UpstreamDiscovery.CompleteRrsetAndCanonicalDedup
UpstreamDiscovery.IgnoreUnrelatedOwnerAndAdditionalRecords
UpstreamDiscovery.CnameChainUsesMinimumTtl
UpstreamDiscovery.CnameFollowupCarriesChainTtlAndRejectsCycles
UpstreamDiscovery.RejectOnlyUnusableUnicastTargets
UpstreamDiscovery.MappedPublicV6DeduplicatesWithA
UpstreamDiscovery.NegativeRevokesImmediatelyNotAtNegativeTtl
UpstreamDiscovery.RefusedAndUnprovedEmptyAreTransientNotNegative
UpstreamDiscovery.NoTransientFailureMeansNoStaleGrace
UpstreamDiscovery.ZeroTtlNeverAdmitsAndRevokesPrevious
UpstreamDiscovery.UnusableTargetDoesNotObtainGrace
UpstreamDiscovery.RrsetOverflowRejectsWholeFamilyNotFirst64
UpstreamDiscovery.NxdomainAndPositiveContradictionDoesNotRefresh
UpstreamDiscovery.WrongQuestionAndUnrelatedSoaCannotRevoke
UpstreamDiscovery.CallbackMayDestroyDiscovery
UpstreamDiscovery.CnameTtlDoesNotRestartAtFollowupResponse
UpstreamDiscovery.LocalAddressesRemainCandidatesForServicePortRecursionCheck
UpstreamDiscovery.EightCnameLinksAllowedNinthRejected
UpstreamDiscovery.TimerFailureBackoffAndDestroyRemovePendingWake
UpstreamDiscovery.CancelledDiscoveryIgnoresLateResultsAndEndReleasesReference
UpstreamDiscovery.ExpiredCnameCannotBeRenewedBySlowerTerminalAnswer
UpstreamDiscovery.KnownFamilyFailureGrantsGraceWhileOtherFamilyStillPending
UpstreamDiscovery.PrivateAndUlaMembershipRefreshIsNotScopeLocked
UpstreamDiscovery.PublicPrivateTransitionsRemainValidAcrossVpnChanges
UpstreamServiceDiscovery.RealBootstrapRrsetStickyAddressWithdrawalAndStableIdentity
UpstreamServiceDiscovery.ExactListenerEndpointRejectedButOtherLoopbackEndpointWorks
UpstreamServicePool.StaticAddressCandidatesReuseOneHealthyExit
UpstreamNodata.RequiresMatchingCompleteInClassAuthorityProof
UpstreamNodata.CompleteHttpsNegativeDoesNotDependOnEarlierProviderRcode
UpstreamNodata.Pool20CountsNodataWithoutDuplicateAttempts
UpstreamNodata.Pool40CountsNodataWithoutDuplicateAttempts
UpstreamNodata.NodataDoesNotCancelOtherProvidersPositive
UpstreamNodata.NxdomainRemainsSuccessfulWithoutDuplicateAttempts
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
AnyAddress.ParentForcedSoaRetainsNativePolicyPrecedence
AnyAddress.ParentLocalBlockRetainsNativeNxdomain
AnyAddress.ChildForcedSoaRetainsPolicyWithoutClaimingUpstreamNodata
AnyAddress.EcsOriginCacheCannotSupplyPlainAddressCompletion
AnyAddress.DoOriginCacheCannotSupplyPlainAddressCompletion
AnyAddress.CdOriginIsRevalidatedAndAdCapabilityReusesCompatibleCache
AnyAddress.ProductionPolicyWarmCachePreservesFourAAndTwoAaaaAcrossAdAndTransport
AnyAddress.NativePolicyCachesRemainIsolatedAcrossInheritedRuleGroups
AnyAddress.BackgroundPrefetchPreservesCompatibleTypedCacheProvenance
AnyAddress.PaddedUpstreamColdAnswersPreserveIndependentValidatedFamilies
AnyAddress.ListenerRoutingSetPoliciesAreInheritedAndIsolateNativeCacheViews
AnyAddress.UnsupportedResponseOptionsCannotBecomePositiveCompletion
AnyBounded.ResponseHopMetadataIsStrippedWithoutChangingAnswers
AnyBounded.MalformedOrViewChangingResponseOptionsCannotEstablishEvidence
HTTP2.Upstream429And503RecoverWithoutPermanentProhibition
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
AnyAddress.DefaultDigAdHintCompletesOverUdpAndTcpWithoutAssertingAd
AnyAddress.CookieAndPaddingDoNotSelectAnUnprovenDnsView
AnyAddress.UnknownEdnsOriginCannotSupplyPlainAddressCompletion
AnyAddress.APlainCallerCannotJoinANonplainOperation
AnyAddress.CnameSuppressionRetainsGenuineUpstreamNodata
AnyAddress.GlobalCnameSuppressionPreservesBothFamiliesAfterAliasValidation
AnyAddress.CnameSuppressionComposesIndependentValidatedNativeAliases
AnyAddress.MultipleUpstreamAliasesFollowTheNativeSelectedAddress
AnyAddress.CnameSuppressionPreservesNativeSelectionAcrossMultipleUpstreams
AnyAddress.ProductionDualstackAndSpeedFlagsComposeWithAddressMode
AnyAddress.Ipv6PolicySuppressionComposesWithAnIpv4Alias
AnyAddress.ProductionIpv6SuppressionAndCnameFlatteningCompose
AnyAddress.Ipv4PolicySuppressionPreservesIpv6
AnyAddress.LocalDualFamilyAddressesDoNotRequireUpstreamProof
AnyAddress.LocalSingleFamilyAddressRetainsNativeMissingFamilyPolicy
AnyAddress.ConfiguredAliasRebasesTargetEvidenceWithoutLosingItsBudget
AnyAddress.ConfiguredAliasRetainsTheTargetsFurtherUpstreamAliases
AnyAddress.ConfiguredAliasAlsoHonorsGlobalCnameSuppression
AnyAddress.NftsetPolicyUsesTheNativeTypedPipeline
AnyAddress.NoCacheBindFlagStillAllowsIndependentTypedResolution
AnyAddress.PolicySuppressionCannotTurnARealTransportFailureIntoSuccess
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
HeaderCompression.EveryOctetUsesTheSameCompleteRfcHuffmanCode
HeaderCompression.BothHuffmanDecodersRejectEosAndInvalidPadding
HeaderCompression.HpackLengthsAndIntegersCannotWrapOrEscapeTheBlock
HeaderCompression.DecoderTableCapacityCannotExceedAdvertisedLimit
HeaderCompression.EncoderSettingsShrinkAndGrowSynchronizeNextHeaderBlock
HeaderCompression.QpackLiteralNameAndValueHaveIndependentHuffmanFlags
HeaderCompression.QpackStaticIndicesNeverNarrowFromLargeIntegers
LIBHTTP2.SettingsHeaderTableSizeEvictsResponseEncoderEntries
LIBHTTP2.OversizedDecoderTableClosesTheConnectionWithCompressionError
LIBHTTP2.SettingsMaxHeaderListSizeLimitsResponseHeaders
UpstreamPolicy.CancellationAlsoStopsPartialWriteContinuation
UpstreamPolicy.UnprogressedWriteMustRecheckSharedRate
UpstreamPolicy.TcpProductionQueueCancelBeforeHandshakeWritesNoBytes
UpstreamPolicy.TcpProductionQueueWritesOneFramedAttemptAfterHandshake
UpstreamPolicy.RetryAfterDateFormsAndInvalidCalendar
UpstreamPolicy.RetainedFailureDoesNotResendAlreadyRepliedEndpoint
UpstreamPolicy.Http1ProductionWriteOwnerBecomesCancellationTombstone
""".split())
QUIC = set("""
Http3Control.MaximumSettingsPayloadFitsWithLongestFrameHeader
QuicEndToEnd.HttpsHttp3QueryRequiresClientSettingsAndReusesTheConnection
QuicEndToEnd.ValidDoqAnswerIsNotDeliveredUntilFin
StrictPeer.FullUnknownStreamSlotsWaitWithoutSpinningAndResumeQueuedControl
Http3Control.DecoderCancellationUsesOnlyQuicStreamIdentifiers
StrictPeer.ProductionWantWriteDoesNotKeepUdpWritableAndResumesOnInput
StrictPeer.IdlePeriodicRetryDoesNotPumpNetworkEvents
StrictPeer.PeriodicRetryDrainsDecodedControlWithoutSyntheticNetworkReadiness
StrictPeer.PeriodicRetryContinuesBudgetDeferredControlFrames
StrictPeer.BufferedWriteRetryDoesNotPretendUdpBecameWritable

UpstreamServiceQuic.RealDoqSingleWanReusesOneHealthyAddress
UpstreamServiceQuic.H3IdleControlKeepaliveUsesNoDnsStreamAndPreservesConnections
UpstreamServiceQuic.RealH3SingleWanReusesOneHealthyAddress
UpstreamServiceQuic.ErrorOnlyDoqReadinessDoesNotSpin
UpstreamServiceQuic.ErrorOnlyH3ReadinessDoesNotSpin
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
Http3Control.GoogleZeroCapacityIsIdempotentAndDoesNotAllowDynamicInstructions
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


# Require the current single-exit policy and resource/PTR regressions too.
COMMON |= set("""
UpstreamServiceState.ABlockedWanWriterCannotHoldAnotherWanTurn
UpstreamServiceState.PerExitAdaptiveCreditsAnd429SurviveServiceAggregation
UpstreamServiceState.DatagramPressureLeavesAnotherWanEligible
UpstreamServiceState.SnapshotCountsHealthyWansNotDormantAlternateFamilies
UpstreamPoolConfig.AdaptiveRateOnlyAppliesToEncryptedNonBootstrapServices
DomainRuleSharing.BulkOverridesGrowthRemovalAndDeletionRemainIndependent
DomainRuleSharing.ExplicitClearAndUnsetAndWildcardScopesStayDistinct
DomainRuleSharing.BoundedPoolFallbackPreservesEveryDistinctValueAcrossTeardown
DomainRuleSharing.LocalPtrPolicyRequiresAnExplicitBooleanAndRejectsWithoutMutation
RefreshQueue.BurstCoalescesBeforeFullRequestAllocationAndIsBounded
RefreshQueue.DedupePreservesFamilyDoAndEcsView
RefreshQueue.BackgroundSourceSurvivesInternalAddressChildFlags
RefreshQueue.ReplacementMakesQueuedWorkRedundantButLruAccessDoesNot
RefreshQueue.QuotaDeadlineDispatchesWhileTheServerWouldOtherwiseBeIdle
LocalPtrPolicy.ReservedPtrPolicyPreservesStaticPublicAndOtherQtypes
LocalPtrPolicy.SpecificOverridesAndInheritedGroupPolicyRemainIndependent
""".split())
QUIC.add('UpstreamServiceQuic.H3CompletedStreamsDoNotConsumeTheLiveStreamLimit')
QUIC.update({
    'UpstreamServiceQuic.PersistentH3ReclaimsRetiredStreams',
    'UpstreamServiceQuic.PersistentDoqReclaimsRetiredStreams',
    'StrictPeerCredit.GcPublishesCreditWithoutFurtherApplicationIo',
})

# Each control must reach its known protocol assertion, rather than fail setup.
OPENSSL_QUIC_REQUIRED = {
    'StateMatrix': 'matrix case 0 send=4 receive=4',
    'ByteCreditOnce': 'ossl_quic_rxfc_get_rwm(&f.connection)==12',
    'MultipleGcAndOwners': 'released-before==7',
    'RetirementFailureRetainsStream': '!collect(&f.map)',
    'NullSendBufferControlLoss': 'loss flags reset=0 stop=0 credit=0',
    'ResetAckThenLateLoss': '!s->want_reset_stream',
    'ResetQueuedLossThenAck': '!s->want_reset_stream',
    'ReceiveFinAfterStop': 'f.stream->ready_for_gc',
    'ReceiveZeroFinCompletes': 'f.stream->ready_for_gc',
    'ResetFinalSizeRetiresUnreadGap': 'ossl_quic_stream_map_get_by_id(&f.map,0)==s',
    'LateAckLossAfterGc': 'released==before+1',
    'IncomingStreamCreditUntilGc': 'ossl_quic_rxfc_get_rwm(count)==0',
}


def validate_dependency(report, evidence_dir=None, sanitizers=None):
    root = Path(__file__).resolve().parents[2]
    spec = json.loads((root / '.github/dependencies/openssl.json').read_text())
    if report['archive_sha256'] != spec['sha256'] or report['patch_sha256'] != hashlib.sha256((root / spec['patch']).read_bytes()).hexdigest():
        raise ValueError('Dependency regression source/patch identity mismatch')
    cases = report['cases']
    if len(cases) != len(OPENSSL_QUIC_REQUIRED) or {c['name'] for c in cases} != set(OPENSSL_QUIC_REQUIRED):
        raise ValueError('Missing/duplicate/unexpected dependency regression')
    if any(c['candidate'] != 0 or c['pristine'] != 1 or c['candidate_completed'] is not True
           or c['pristine_expected_failure'] is not True or c['sanitizer_clean'] is not True for c in cases):
        raise ValueError('Dependency regression/real pristine negative control did not complete as required')
    if set(report['variants']) != {'candidate', 'pristine'}:
        raise ValueError('Both exact dependency variants required')
    control = report['native_credit_control']
    if (control['case'] != 'StrictPeerCredit.GcPublishesCreditWithoutFurtherApplicationIo'
            or control['candidate'] != 0 or control['pristine'] != 1
            or control['qualified_failure'] is not True or not control['unchanged_objects']):
        raise ValueError('Real native credit/scheduling negative control did not qualify')
    if sanitizers is not None and report['sanitizers'] is not sanitizers:
        raise ValueError('Dependency sanitizer policy differs from this job')
    if evidence_dir is not None:
        inputs = []
        for variant in ['candidate', 'pristine']:
            receipt = json.loads((evidence_dir / ('openssl-' + variant + '.json')).read_text())
            value = dict(receipt['input'])
            if (value['archive_sha256'] != spec['sha256'] or value['version'] != spec['version']
                    or value['recipe_sha256'] != hashlib.sha256((root / '.github/scripts/openssl-dependency.py').read_bytes()).hexdigest()
                    or value['pristine'] is not (variant == 'pristine')
                    or value['patch_sha256'] != (report['patch_sha256'] if variant == 'candidate' else None)
                    or value['sanitizers'] is not report['sanitizers']):
                raise ValueError('Dependency receipt does not match tested source/variant')
            binary_sha = report['variants'][variant]['binary_sha256']
            if len(binary_sha) != 64 or any(c not in '0123456789abcdef' for c in binary_sha):
                raise ValueError('Missing exact dependency test executable identity')
            for name in ['lib/libssl.a', 'lib/libcrypto.a']:
                if receipt['files'][name]['size'] <= 0 or len(receipt['files'][name]['sha256']) != 64:
                    raise ValueError('Missing installed static archive identity')
            value.pop('pristine'); value.pop('patch_sha256'); inputs.append(value)
        if inputs[0] != inputs[1]:
            raise ValueError('Pristine and candidate must differ only by the repair patch')
    print(f'Accepted {len(cases)} patched/pristine dependency regression pairs.')


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
    root = Path(__file__).resolve().parents[2]
    spec = json.loads((root / '.github/dependencies/openssl.json').read_text())
    dependency = {
        'archive_sha256': spec['sha256'],
        'patch_sha256': hashlib.sha256((root / spec['patch']).read_bytes()).hexdigest(),
        'sanitizers': False, 'variants': {'candidate': {}, 'pristine': {}},
        'cases': [{'name': name, 'candidate': 0, 'pristine': 1,
                   'candidate_completed': True, 'pristine_expected_failure': True, 'sanitizer_clean': True}
                  for name in OPENSSL_QUIC_REQUIRED],
        'native_credit_control': {
            'case': 'StrictPeerCredit.GcPublishesCreditWithoutFurtherApplicationIo',
            'candidate': 0, 'pristine': 1, 'qualified_failure': True,
            'unchanged_objects': {'test-only-synthetic.o': 'synthetic'},
        },
    }
    validate_dependency(dependency, sanitizers=False)
    for kind in ('missing', 'duplicate', 'old-passes', 'wrong-assertion', 'sanitizer', 'wrong-source', 'native-unqualified'):
        report = json.loads(json.dumps(dependency))
        if kind == 'missing': report['cases'].pop()
        elif kind == 'duplicate': report['cases'][0] = report['cases'][1]
        elif kind == 'old-passes': report['cases'][0]['pristine'] = 0
        elif kind == 'wrong-assertion': report['cases'][0]['pristine_expected_failure'] = False
        elif kind == 'sanitizer': report['cases'][0]['sanitizer_clean'] = False
        elif kind == 'wrong-source': report['archive_sha256'] = '0' * 64
        elif kind == 'native-unqualified': report['native_credit_control']['qualified_failure'] = False
        try:
            validate_dependency(report, sanitizers=False)
        except ValueError:
            continue
        raise AssertionError('bad dependency control accepted: ' + kind)
    print('Dependency result-gate synthetic positive/negative checks passed; no dependency executed.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--profile', choices=('system', 'quic'))
    parser.add_argument('--sanitizers', choices=('0', '1'))
    parser.add_argument('xml', nargs='?')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.profile or not args.xml:
        parser.error('--profile and XML path required')
    try:
        validate(ET.parse(args.xml).getroot(), args.profile)
        if args.profile == 'quic':
            validate_dependency(json.loads(Path(args.xml).with_name('openssl-quic-tests.json').read_text()),
                                Path(args.xml).parent, None if args.sanitizers is None else args.sanitizers == '1')
    except (OSError, ET.ParseError, ValueError, KeyError, TypeError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
