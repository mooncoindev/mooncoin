// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "chain.h"
#include "chainparams.h"
#include "primitives/block.h"
#include "bignum.h"
#include "uint256.h"
#include "util.h"

typedef int64_t int64;
typedef uint64_t uint64;

static CBigNum bnProofOfWorkLimit(~uint256(0) >> 20);

unsigned int GetNextWorkRequired_V1(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
{
    unsigned int nProofOfWorkLimit = Params().ProofOfWorkLimit().GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    // Only change once per interval
    if ((pindexLast->nHeight+1) % Params().Interval() != 0)
    {
        // Special difficulty rule for testnet:
        if (Params().AllowMinDifficultyBlocks())
        {
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->nTime > pindexLast->nTime + Params().TargetSpacing()*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % Params().Interval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }

        return pindexLast->nBits;
    }

    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = Params().Interval() - 1;
    if ((pindexLast->nHeight+1) != Params().Interval())
        blockstogoback = Params().Interval();

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;
    assert(pindexFirst);

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    LogPrintf("  nActualTimespan = %d  before bounds\n", nActualTimespan);

       if(pindexLast->nHeight+1 > 10000)
        {
                if (nActualTimespan < Params().TargetTimespan()/4)
                        nActualTimespan = Params().TargetTimespan()/4;
                if (nActualTimespan > Params().TargetTimespan()*4)
                        nActualTimespan = Params().TargetTimespan()*4;
        }
        else if(pindexLast->nHeight+1 > 5000)
        {
                if (nActualTimespan < Params().TargetTimespan()/8)
                        nActualTimespan = Params().TargetTimespan()/8;
                if (nActualTimespan > Params().TargetTimespan()*4)
                        nActualTimespan = Params().TargetTimespan()*4;
        }
        else
        {
                if (nActualTimespan < Params().TargetTimespan()/16)
                        nActualTimespan = Params().TargetTimespan()/16;
                if (nActualTimespan > Params().TargetTimespan()*4)
                        nActualTimespan = Params().TargetTimespan()*4;
        }

    // Retarget
    uint256 bnNew;
    uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    bnNew *= nActualTimespan;
    bnNew /= Params().TargetTimespan();

    if (bnNew > Params().ProofOfWorkLimit())
        bnNew = Params().ProofOfWorkLimit();

    /// debug print
	if(fDebug){
		LogPrintf("GetNextWorkRequired RETARGET\n");
		LogPrintf("Params().TargetTimespan() = %d    nActualTimespan = %d\n", Params().TargetTimespan(), nActualTimespan);
		LogPrintf("Before: %08x  %s\n", pindexLast->nBits, bnOld.ToString());
		LogPrintf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());
	}
	
    return bnNew.GetCompact();
}

unsigned int KimotoGravityWell(const CBlockIndex* pindexLast, const CBlockHeader *pblock, uint64_t TargetBlocksSpacingSeconds, uint64_t PastBlocksMin, uint64_t PastBlocksMax) {
    /* current difficulty formula, megacoin - kimoto gravity well */
    const CBlockIndex  *BlockLastSolved                             = pindexLast;
    const CBlockIndex  *BlockReading                                = pindexLast;
    const CBlockHeader *BlockCreating                               = pblock;
                        BlockCreating                               = BlockCreating;
    uint64                                PastBlocksMass                       = 0;
    int64                                 PastRateActualSeconds                = 0;
    int64                                 PastRateTargetSeconds                = 0;
    double                                PastRateAdjustmentRatio              = double(1);
    CBigNum                               PastDifficultyAverage;
    CBigNum                               PastDifficultyAveragePrev;
    double                                EventHorizonDeviation;
    double                                EventHorizonDeviationFast;
    double                                EventHorizonDeviationSlow;

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64)BlockLastSolved->nHeight < PastBlocksMin) { return bnProofOfWorkLimit.GetCompact(); }

  	for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
		if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
		PastBlocksMass++;
		
		if (i == 1)	{ PastDifficultyAverage.SetCompact(BlockReading->nBits); }
		else		{ PastDifficultyAverage = ((CBigNum().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev; }
		PastDifficultyAveragePrev = PastDifficultyAverage;
		
		PastRateActualSeconds			= BlockLastSolved->GetBlockTime() - BlockReading->GetBlockTime();
		PastRateTargetSeconds			= TargetBlocksSpacingSeconds * PastBlocksMass;
		PastRateAdjustmentRatio			= double(1);
		if (PastRateActualSeconds < 0) { PastRateActualSeconds = 0; }
		if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
		PastRateAdjustmentRatio			= double(PastRateTargetSeconds) / double(PastRateActualSeconds);
		}
		EventHorizonDeviation			= 1 + (0.7084 * pow((double(PastBlocksMass)/double(144)), -1.228));
		EventHorizonDeviationFast		= EventHorizonDeviation;
		EventHorizonDeviationSlow		= 1 / EventHorizonDeviation;
		
		if (PastBlocksMass >= PastBlocksMin) {
			if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) { assert(BlockReading); break; }
		}
		if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
		BlockReading = BlockReading->pprev;
	}
	
	CBigNum bnNew(PastDifficultyAverage);
	if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
		bnNew *= PastRateActualSeconds;
		bnNew /= PastRateTargetSeconds;
	}
    if (bnNew > bnProofOfWorkLimit) { bnNew = bnProofOfWorkLimit; }
 
    if(fDebug){
		/// debug print
		LogPrintf("Difficulty Retarget - KGW Wormhole\n");
		LogPrintf("PastRateAdjustmentRatio = %g\n", PastRateAdjustmentRatio);
		LogPrintf("Before: %08x  %s\n", BlockLastSolved->nBits, CBigNum().SetCompact(BlockLastSolved->nBits).getuint256().ToString().c_str());
		LogPrintf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());
    }
	
    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired_V2(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
{
    static const int64_t        BlocksTargetSpacing                        = 90;
    unsigned int                TimeDaySeconds                             = 60 * 60 * 24;
    int64_t                     PastSecondsMin                             = TimeDaySeconds * 0.25;
    int64_t                     PastSecondsMax                             = TimeDaySeconds * 7;
    uint64_t                    PastBlocksMin                              = PastSecondsMin / BlocksTargetSpacing;
    uint64_t                    PastBlocksMax                              = PastSecondsMax / BlocksTargetSpacing;

    return KimotoGravityWell(pindexLast, pblock, BlocksTargetSpacing, PastBlocksMin, PastBlocksMax);
}

unsigned int static DigiShield(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
{
    // DigiShield difficulty retarget system
    unsigned int nProofOfWorkLimit = bnProofOfWorkLimit.GetCompact();
    bool fTestNet = false;
    int blockstogoback = 0;
    int64 nTargetSpacing = 1 * 90;             // target 90 sec
    int64 retargetTimespan = nTargetSpacing;
    int64 retargetSpacing = nTargetSpacing;
    int64 retargetInterval = retargetTimespan / retargetSpacing;
	
    // Genesis block
    if (pindexLast == NULL) return nProofOfWorkLimit;

    // Only change once per interval
    if ((pindexLast->nHeight+1) % retargetInterval != 0){
      // Special difficulty rule for testnet:
        if (fTestNet){
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->nTime > pindexLast->nTime + retargetSpacing*2)
                return nProofOfWorkLimit;
        else {
            // Return the last non-special-min-difficulty-rules-block
            const CBlockIndex* pindex = pindexLast;
            while (pindex->pprev && pindex->nHeight % retargetInterval != 0 && pindex->nBits == nProofOfWorkLimit)
            pindex = pindex->pprev;
        return pindex->nBits;
        }
      }
      return pindexLast->nBits;
    }

    // DigiByte: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    blockstogoback = retargetInterval-1;
    if ((pindexLast->nHeight+1) != retargetInterval) blockstogoback = retargetInterval;

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;
    assert(pindexFirst);

    // Limit adjustment step
    int64 nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    LogPrintf("  nActualTimespan = %g before bounds\n", nActualTimespan);

    CBigNum bnNew;
    bnNew.SetCompact(pindexLast->nBits);

    if (nActualTimespan < (retargetTimespan - (retargetTimespan/4)) ) nActualTimespan = (retargetTimespan - (retargetTimespan/4));
    if (nActualTimespan > (retargetTimespan + (retargetTimespan/2)) ) nActualTimespan = (retargetTimespan + (retargetTimespan/2));

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= retargetTimespan;

    /// debug print
    LogPrintf("DigiShield RETARGET \n");
    LogPrintf("retargetTimespan = %g    nActualTimespan = %g \n", retargetTimespan, nActualTimespan);
    LogPrintf("Before: %08x  %s\n", pindexLast->nBits, CBigNum().SetCompact(pindexLast->nBits).getuint256().ToString().c_str());
    LogPrintf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());

    if (bnNew > bnProofOfWorkLimit)
        bnNew = bnProofOfWorkLimit;

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
{
 int DiffMode = 1; 
 if (pindexLast->nHeight+1 < 26850)    { DiffMode = 1; }
 if (pindexLast->nHeight+1 >= 26850)   { DiffMode = 2; }
 if (pindexLast->nHeight+1 >= 1100000) { DiffMode = 3; }
 if (DiffMode == 1) { return GetNextWorkRequired_V1(pindexLast, pblock); }
 if (DiffMode == 2) { return GetNextWorkRequired_V2(pindexLast, pblock); }
 if (DiffMode == 3) { return DigiShield(pindexLast, pblock); }
 return DigiShield(pindexLast, pblock);
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    bool fNegative;
    bool fOverflow;
    uint256 bnTarget;

    if (Params().SkipProofOfWorkCheck())
       return true;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > Params().ProofOfWorkLimit())
        return error("CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget)
        return error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

uint256 GetBlockProof_old(const CBlockIndex& block)
{
    uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

uint256 GetBlockProof(const CBlockIndex& block)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(block.nBits);
    if (bnTarget <= 0)
        return 0;
    return ((CBigNum(1)<<256) / (bnTarget+1)).getuint256();;
}
