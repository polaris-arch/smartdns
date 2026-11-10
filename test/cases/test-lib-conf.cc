/*************************************************************************
 *
 * Copyright (C) 2018-2026 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


/* Native default certificates remain relative to the top-level config. */
#include "gtest/gtest.h"
#include "include/utils.h"
#include "server.h"
#include <cstdlib>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

TEST(LibConf, DefaultTlsCertificatesStayBesideTheTopConfiguration)
{
	char directory[] = "/tmp/smartdns-conf-path.XXXXXX";
	ASSERT_NE(mkdtemp(directory), nullptr);
	std::string root = directory, config_dir = root + "/config", work_dir = root + "/work";
	ASSERT_EQ(mkdir(config_dir.c_str(), 0700), 0);
	ASSERT_EQ(mkdir(work_dir.c_str(), 0700), 0);
	const char *old_workdir = getenv("SMARTDNS_WORKDIR");
	bool had_workdir = old_workdir != nullptr;
	std::string saved_workdir = old_workdir ? old_workdir : "";
	Defer {
		if (had_workdir) setenv("SMARTDNS_WORKDIR", saved_workdir.c_str(), 1);
		else unsetenv("SMARTDNS_WORKDIR");
		unlink((config_dir + "/smartdns.conf").c_str());
		for (const auto &dir : {config_dir, work_dir}) {
			for (const char *name : {"smartdns-cert.pem", "smartdns-key.pem", "smartdns-root-key.pem"})
				unlink((dir + "/" + name).c_str());
		}
		rmdir(config_dir.c_str()); rmdir(work_dir.c_str()); rmdir(root.c_str());
	};
	std::string config_file = config_dir + "/smartdns.conf";
	std::ofstream conf(config_file);
	conf << "bind-tls 127.0.0.1:60053\nserver 127.0.0.1:61053\n"
		"cache-persist no\nlog-console yes\nlog-num 0\n";
	conf.close();
	ASSERT_TRUE(conf.good());
	ASSERT_EQ(setenv("SMARTDNS_WORKDIR", work_dir.c_str(), 1), 0);
	smartdns::Server server;
	ASSERT_TRUE(server.Start(config_file, smartdns::Server::CONF_TYPE_FILE));
	for (const char *name : {"smartdns-cert.pem", "smartdns-key.pem", "smartdns-root-key.pem"}) {
		EXPECT_EQ(access((config_dir + "/" + name).c_str(), F_OK), 0);
		EXPECT_NE(access((work_dir + "/" + name).c_str(), F_OK), 0);
	}
	server.Stop();
}
