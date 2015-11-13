//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// General-purpose methods for handling filesystem pathnames

#ifndef OPENVPN_COMMON_PATH_H
#define OPENVPN_COMMON_PATH_H

#include <string>

#include <openvpn/common/types.hpp>
#include <openvpn/common/platform.hpp>
#include <openvpn/common/string.hpp>

namespace openvpn {
  namespace path {

    // Directory separators.  The first char in dirsep is the primary
    // separator for the platform, while subsequent chars are also
    // recognized as separators.
#if defined(OPENVPN_PLATFORM_WIN) || defined(OPENVPN_PATH_SIMULATE_WINDOWS)
    // Windows
    const char dirsep[] = "\\/"; // CONST GLOBAL
#else
    // Unix
    const char dirsep[] = "/\\"; // CONST GLOBAL
#endif

    // true if char is a directory separator
    inline bool is_dirsep(const char c)
    {
      for (const char *p = dirsep; *p != '\0'; ++p)
	if (c == *p)
	  return true;
      return false;
    }

    inline bool win_dev(const std::string& path, const bool fully_qualified)
    {
#if defined(OPENVPN_PLATFORM_WIN) || defined(OPENVPN_PATH_SIMULATE_WINDOWS)
      // Identify usage such as "c:\\".
      return path.length() >= 3
	&& ((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z'))
	&& path[1] == ':'
	&& (!fully_qualified || is_dirsep(path[2]));
#else
      return false;
#endif
    }

    // true if path is fully qualified
    inline bool is_fully_qualified(const std::string& path)
    {
      return win_dev(path, true) || (path.length() > 0 && is_dirsep(path[0]));
    }

    // does path refer to regular file without directory traversal
    inline bool is_flat(const std::string& path)
    {
      return path.length() > 0
	&& path != "."
	&& path != ".."
	&& path.find_first_of(dirsep) == std::string::npos
	&& !win_dev(path, false);
    }

    inline std::string basename(const std::string& path)
    {
      const size_t pos = path.find_last_of(dirsep);
      if (pos != std::string::npos)
	{
	  const size_t p = pos + 1;
	  if (p >= path.length())
	    return "";
	  else
	    return path.substr(p);
	}
      else
	return path;
    }

    inline std::string dirname(const std::string& path)
    {
      const size_t pos = path.find_last_of(dirsep);
      if (pos != std::string::npos)
	{
	  if (pos == 0)
	    return "/";
	  else
	    return path.substr(0, pos);
	}
      else
	return "";
    }

    inline std::string ext(const std::string& basename)
    {
      const size_t pos = basename.find_last_of('.');
      if (pos != std::string::npos)
	{
	  const size_t p = pos + 1;
	  if (p >= basename.length())
	    return "";
	  else
	    return basename.substr(p);
	}
      else
	return "";
    }

    inline std::string join(const std::string& p1, const std::string& p2)
    {
      if (p1.empty() || is_fully_qualified(p2))
	return p2;
      else
	return string::add_trailing(p1, dirsep[0]) + p2;
    }

  } // namespace path
} // namespace openvpn

#endif // OPENVPN_COMMON_STRING_H
