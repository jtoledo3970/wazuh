/*
 * Wazuh SysCollector
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "containerFreshness.hpp"

#include <gtest/gtest.h>

#include <set>

#include <unistd.h>

namespace
{
    using Clock = LockHolders::Clock;
    using std::chrono::seconds;

    const auto ADMIT_ALL = [](const std::string&)
    {
        return true;
    };

    /// Liveness by a set the test edits: a holder is alive while listed.
    struct Processes
    {
        std::set<std::pair<int, std::uint64_t>> running;

        LockHolders::IsAlive isAlive() const
        {
            return [this](int pid, std::uint64_t startTime)
            {
                return running.count({pid, startTime}) != 0;
            };
        }

        /// Starts a process and returns what /proc would say about it.
        ProcStat start(int pid, std::uint64_t startTime, int parentPid)
        {
            running.insert({pid, startTime});
            return ProcStat {startTime, parentPid};
        }

        void exit(int pid, std::uint64_t startTime)
        {
            running.erase({pid, startTime});
        }
    };

    const std::string FILLERS = " 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21";
} // namespace

TEST(ContainerFreshnessLockPathTest, EveryPackageLockMatches)
{
    for (const auto& path : packageLockPaths())
    {
        EXPECT_TRUE(isPackageLockPath(path)) << path;
    }

    EXPECT_TRUE(isPackageLockPath("/usr/lib/apk/db/lock")) << "apk's lock on a merged /usr";
}

TEST(ContainerFreshnessLockPathTest, OtherFilesNamedLikeALockDoNot)
{
    EXPECT_FALSE(isPackageLockPath("/var/lib/apt/lists/lock"));
    EXPECT_FALSE(isPackageLockPath("/var/cache/apt/archives/lock"));
    EXPECT_FALSE(isPackageLockPath("/var/lib/docker/overlay2/abc/diff/var/lib/dpkg/lock"));
    EXPECT_FALSE(isPackageLockPath("/var/lib/dpkg/status"));
    EXPECT_FALSE(isPackageLockPath("/var/lib/rpm/rpmdb.sqlite-wal"));
}

TEST(ContainerFreshnessLockPathTest, TheFilterNamesCoverEveryLock)
{
    const std::set<std::string> names {packageLockNames().begin(), packageLockNames().end()};

    for (const auto& path : packageLockPaths())
    {
        EXPECT_EQ(names.count(path.substr(path.rfind('/') + 1)), 1u) << path;
    }
}

TEST(ContainerFreshnessProcStatTest, ReadsTheParentAndStartTimePastAnOddComm)
{
    // Field 4 is 7; fields 5..21 are fillers; field 22 is 98765.
    const auto stat = parseProcStat("42 (a) b (c)) S 7" + FILLERS + " 98765 0 0");
    ASSERT_TRUE(stat);
    EXPECT_EQ(stat->parentPid, 7);
    EXPECT_EQ(stat->startTime, 98765u);
}

TEST(ContainerFreshnessProcStatTest, AZombieOrAShortLineIsGone)
{
    EXPECT_FALSE(parseProcStat("42 (dpkg) Z 7" + FILLERS + " 98765 0 0"));
    EXPECT_FALSE(parseProcStat("42 (dpkg) X 7" + FILLERS + " 98765 0 0"));
    EXPECT_FALSE(parseProcStat("42 (dpkg) S 1 2"));
    EXPECT_FALSE(parseProcStat(""));
}

TEST(ContainerFreshnessProcStatTest, ARunningProcessHasAStatAndAMissingOneDoesNot)
{
#if defined(__linux__)
    const auto self = processStat(static_cast<int>(::getpid()));
    ASSERT_TRUE(self);
    EXPECT_EQ(self->parentPid, static_cast<int>(::getppid()));
    EXPECT_EQ(processStat(static_cast<int>(::getpid()))->startTime, self->startTime) << "stable while it runs";
    EXPECT_FALSE(processStat(-1));
#else
    GTEST_SKIP() << "/proc is Linux-only";
#endif
}

TEST(ContainerFreshnessProcStatTest, AProcessStartedAfterTheEventReusedThePid)
{
    // 100 ticks per second: a tick is 10 ms.
    EXPECT_FALSE(startedAfter(100, 100, 1000000000ULL)) << "started at the event";
    EXPECT_FALSE(startedAfter(101, 100, 1000000000ULL)) << "within one tick";
    EXPECT_TRUE(startedAfter(150, 100, 1000000000ULL));
}

TEST(ContainerFreshnessLockHoldersTest, AnAptRunIsDueOnceWhenAptGetExits)
{
    LockHolders holders {seconds{30}};
    Processes processes;
    const auto t0 = Clock::time_point {} + seconds{1000};

    // apt-get (10, its parent the shell 1) takes lock-frontend; each dpkg run
    // it starts takes the lock as its child.
    holders.note("a", 10, processes.start(10, 1, 1));
    holders.note("a", 11, processes.start(11, 2, 10));
    processes.exit(11, 2);
    EXPECT_TRUE(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL).empty()) << "the unpack run is not the end";

    holders.note("a", 12, processes.start(12, 3, 10));
    processes.exit(12, 3);
    EXPECT_TRUE(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL).empty()) << "nor the configure run";
    EXPECT_TRUE(holders.hasHolders());

    processes.exit(10, 1);
    EXPECT_EQ(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));
    EXPECT_TRUE(holders.takeDue(t0 + seconds{60}, processes.isAlive(), ADMIT_ALL).empty()) << "served once";
    EXPECT_FALSE(holders.hasHolders());
}

TEST(ContainerFreshnessLockHoldersTest, ChainedInstallsAreEachDueWhenTheyEnd)
{
    LockHolders holders {seconds{30}};
    Processes processes;
    const auto t0 = Clock::time_point {} + seconds{1000};

    // The next install takes the lock before the first one's exit is seen.
    holders.note("a", 10, processes.start(10, 1, 1));
    processes.exit(10, 1);
    holders.note("a", 20, processes.start(20, 2, 1));
    EXPECT_EQ(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}))
            << "the first install is reported while the second runs";

    processes.exit(20, 2);
    EXPECT_EQ(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));
}

TEST(ContainerFreshnessLockHoldersTest, AHolderThatNeverExitsHoldsBackNoOtherInstall)
{
    LockHolders holders {seconds{30}};
    Processes processes;
    const auto t0 = Clock::time_point {} + seconds{1000};

    // A process that opened the lock and stays, then an install beside it.
    holders.note("a", 10, processes.start(10, 1, 1));
    holders.note("a", 20, processes.start(20, 2, 1));
    processes.exit(20, 2);
    EXPECT_EQ(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));
    EXPECT_TRUE(holders.hasHolders()) << "still checked while it runs";
}

TEST(ContainerFreshnessLockHoldersTest, AChildIsReadOnItsOwnOnceItsParentIsGone)
{
    LockHolders holders {seconds{30}};
    Processes processes;
    const auto t0 = Clock::time_point {} + seconds{1000};

    // apt-get interrupted while its dpkg run goes on.
    holders.note("a", 10, processes.start(10, 1, 1));
    holders.note("a", 11, processes.start(11, 2, 10));
    processes.exit(10, 1);
    EXPECT_EQ(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));

    processes.exit(11, 2);
    EXPECT_EQ(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}))
            << "the orphaned run's work is read when it ends";
}

TEST(ContainerFreshnessLockHoldersTest, AHolderAlreadyGoneIsDueUnlessAnotherStillRuns)
{
    LockHolders holders {seconds{30}};
    Processes processes;
    const auto t0 = Clock::time_point {} + seconds{1000};

    holders.note("a", 10, std::nullopt);
    EXPECT_FALSE(holders.hasHolders());
    EXPECT_EQ(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));

    // A dpkg run that ended before it was read, inside a running apt-get.
    holders.note("b", 20, processes.start(20, 1, 1));
    holders.note("b", 21, std::nullopt);
    EXPECT_TRUE(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL).empty());
    processes.exit(20, 1);
    EXPECT_EQ(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"b"}));
}

TEST(ContainerFreshnessLockHoldersTest, ARunningPidWithAnotherStartTimeHasExited)
{
    LockHolders holders {seconds{30}};
    Processes processes;
    const auto t0 = Clock::time_point {} + seconds{1000};

    holders.note("a", 10, ProcStat {1, 1});
    processes.running = {{10, 7}};
    EXPECT_EQ(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));
}

TEST(ContainerFreshnessLockHoldersTest, OneProcessOpeningSeveralLocksIsOneHolder)
{
    LockHolders holders {seconds{30}};
    Processes processes;
    const auto t0 = Clock::time_point {} + seconds{1000};

    // apt-get opens lock-frontend and the lock; yum opens the lock twice.
    const auto stat = processes.start(10, 1, 1);
    holders.note("a", 10, stat);
    holders.note("a", 10, stat);
    holders.note("a", 10, stat);

    processes.exit(10, 1);
    EXPECT_EQ(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));
    EXPECT_TRUE(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL).empty());
}

TEST(ContainerFreshnessLockHoldersTest, ContainersAreIndependent)
{
    LockHolders holders {seconds{30}};
    Processes processes;
    const auto t0 = Clock::time_point {} + seconds{1000};

    holders.note("a", 10, processes.start(10, 1, 1));
    holders.note("b", 20, processes.start(20, 1, 1));

    processes.exit(10, 1);
    EXPECT_EQ(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));
}

TEST(ContainerFreshnessLockHoldersTest, ANonAdmittedContainerIsDroppedNotRefreshed)
{
    LockHolders holders {seconds{30}};
    Processes processes;
    const auto t0 = Clock::time_point {} + seconds{1000};

    holders.note("a", 10, std::nullopt);
    const auto due = holders.takeDue(t0, processes.isAlive(), [](const std::string & id)
    {
        return id != "a";
    });

    EXPECT_TRUE(due.empty());
    EXPECT_TRUE(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL).empty()) << "dropped, not kept";
}

TEST(ContainerFreshnessLockHoldersTest, AChangedContainerIsDueAtOnceAndAgainAFollowUpLater)
{
    LockHolders holders {seconds{30}};
    Processes processes;
    const auto t0 = Clock::time_point {} + seconds{1000};

    // Even while a known holder still runs: its own exit is reported later.
    holders.note("a", 10, processes.start(10, 1, 1));
    holders.markChanged("a", t0);

    EXPECT_EQ(holders.takeDue(t0, processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));
    EXPECT_TRUE(holders.takeDue(t0 + seconds{29}, processes.isAlive(), ADMIT_ALL).empty());
    EXPECT_EQ(holders.takeDue(t0 + seconds{30}, processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));

    processes.exit(10, 1);
    EXPECT_EQ(holders.takeDue(t0 + seconds{31}, processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}))
            << "the holder's exit";
    EXPECT_TRUE(holders.takeDue(t0 + seconds{90}, processes.isAlive(), ADMIT_ALL).empty());
}

TEST(ContainerFreshnessLockHoldersTest, ClearForgetsEverything)
{
    LockHolders holders {seconds{30}};
    Processes processes;
    const auto t0 = Clock::time_point {} + seconds{1000};

    holders.note("a", 10, processes.start(10, 1, 1));
    holders.markChanged("b", t0);
    holders.clear();

    EXPECT_FALSE(holders.hasHolders());
    EXPECT_TRUE(holders.takeDue(t0 + seconds{60}, processes.isAlive(), ADMIT_ALL).empty());
}
