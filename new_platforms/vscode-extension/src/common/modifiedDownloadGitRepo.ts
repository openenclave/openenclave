// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
"use strict";

interface IDownloadOptions {
    clone?: boolean;
}

interface INormalizedRepo {
    type: string;
    origin?: string;
    owner?: string | null;
    name?: string | null;
    url?: string | null;
    checkout: string;
}

export class GitClone {
  /**
   * Download `repo` to `dest` and callback `fn(err)`.
   *
   * @param {String} repo
   * @param {String} dest
   * @param {Object} opts
   * @param {Function} fn
   */

  public static download(specifiedRepo: string, dest: string, opts?: IDownloadOptions, fn?: any) {
    opts = opts || {};
    const clone = opts.clone || false;

    const repo = GitClone.normalize(specifiedRepo);
    const url = GitClone.getUrl(repo, clone);

    if (clone) {
      const gitclone = require("git-clone");
      gitclone(url, dest, { checkout: repo.checkout, shallow: repo.checkout === "master" }, (err: Error) => {
        if (err === undefined) {
          fn();
        } else {
          fn(err);
        }
      });
    } else {
      const downloadUrl = require("download");
      downloadUrl(url, dest, { extract: true, strip: 1, mode: "666", headers: { accept: "application/zip" } })
        .then((data: any) => {
          fn();
        })
        .catch((err: Error) => {
          fn(err);
        });
    }
  }

  /**
   * Normalize a repo string.
   *
   * @param {String} repo
   * @return {Object}
   */

  private static normalize(repo: string): INormalizedRepo {
    const directRegex = new RegExp("^(?:(direct):([^#]+)(?:#(.+))?)$");
    const directMatch = directRegex.exec(repo);

    if (directMatch) {
      return {
        type: "direct",
        url: directMatch[2],
        checkout: (directMatch[3] || "master"),
      };
    } else {
      const regex = new RegExp("^(?:(github|gitlab|bitbucket):)?(?:(.+):)?([^\/]+)\/([^#]+)(?:#(.+))?$");
      const match = regex.exec(repo);
      const normalizedRepo: INormalizedRepo = {
        type: (match && match[1]) || "github",
        checkout: (match && match[5]) || "master",
        owner: (match && match[3]),
        name: (match && match[4]),
      };

      if (match && match[2]) {
        normalizedRepo.origin = match[2];
      } else {
        if (normalizedRepo.type === "gitlab") {
          normalizedRepo.origin = "gitlab.com";
        } else if (normalizedRepo.type === "bitbucket") {
          normalizedRepo.origin = "bitbucket.com";
        } else /*if (normalizedRepo.type === "github")*/ {
          normalizedRepo.origin = "github.com";
        }
      }

      return normalizedRepo;
    }
  }

  /**
   * Adds protocol to url in none specified
   *
   * @param {String} url
   * @return {String}
   */

  private static addProtocol(origin: string | undefined, clone: boolean) {
    const regex = new RegExp("!^(f|ht)tps?:\/\/", "i");
    if (origin) {
      if (regex.test(origin)) {
        if (clone) {
          return "git@" + origin;
        } else {
          return "https://" + origin;
        }
      }
    }

    return origin;
  }

  /**
   * Return a zip or git url for a given `repo`.
   *
   * @param {Object} repo
   * @return {String}
   */

  private static getUrl(repo: INormalizedRepo, clone: boolean) {
    if (repo.url) {
        return repo.url;
    }

    // Get origin with protocol and add trailing slash or colon (for ssh)
    let origin = GitClone.addProtocol(repo.origin, clone);
    if (origin) {
      const regex = new RegExp("^git\@", "i");
      if (regex.test(origin)) {
        origin = origin + ":";
      } else {
        origin = origin + "/";
      }

      // Build url
      if (clone) {
        return origin + repo.owner + "/" + repo.name + ".git";
      } else {
        if (repo.type === "github") {
          return origin + repo.owner + "/" + repo.name + "/archive/" + repo.checkout + ".zip";
        } else if (repo.type === "gitlab") {
          return origin + repo.owner + "/" + repo.name + "/repository/archive.zip?ref=" + repo.checkout;
        } else if (repo.type === "bitbucket") {
          return origin + repo.owner + "/" + repo.name + "/get/" + repo.checkout + ".zip";
        }
      }
    }

    return undefined;
  }
}
