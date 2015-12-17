package org.jenkinsci.plugins.ghprb;

import hudson.Extension;
import hudson.model.AbstractProject;
import hudson.model.UnprotectedRootAction;
import hudson.security.ACL;
import hudson.security.csrf.CrumbExclusion;
import jenkins.model.Jenkins;

import org.acegisecurity.Authentication;
import org.acegisecurity.context.SecurityContextHolder;
import org.apache.commons.io.IOUtils;
import org.kohsuke.github.GHEventPayload.IssueComment;
import org.kohsuke.github.GHEventPayload.PullRequest;
import org.kohsuke.github.GHIssueState;
import org.kohsuke.github.GitHub;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GHPullRequest;
import org.kohsuke.github.GHCommit;
import org.kohsuke.github.GHCommit.File;
import org.kohsuke.github.GHPullRequestCommitDetail;
import com.coravy.hudson.plugins.github.GithubProjectProperty;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.HashSet;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * @author Honza Brázdil <jbrazdil@redhat.com>
 */
@Extension
public class GhprbRootAction implements UnprotectedRootAction {
    static final String URL = "ghprbhook";
    private static final Logger logger = Logger.getLogger(GhprbRootAction.class.getName());

    public String getIconFileName() {
        return null;
    }

    public String getDisplayName() {
        return null;
    }

    public String getUrlName() {
        return URL;
    }

    public void doIndex(StaplerRequest req, StaplerResponse resp) {
        String event = req.getHeader("X-GitHub-Event");
        String signature = req.getHeader("X-Hub-Signature");
        String type = req.getContentType();
        String payload = null;
        String body = null;

        if ("application/json".equals(type)) {
            body = extractRequestBody(req);
            if (body == null) {
                logger.log(Level.SEVERE, "Can't get request body for application/json.");
                return;
            }
            payload = body;
        } else if ("application/x-www-form-urlencoded".equals(type)) {
            body = extractRequestBody(req);
            if (body == null || body.length() <= 8) {
                logger.log(Level.SEVERE, "Request doesn't contain payload. "
                        + "You're sending url encoded request, so you should pass github payload through 'payload' request parameter");
                return;
            }
            try {
                String encoding = req.getCharacterEncoding();
                payload = URLDecoder.decode(body.substring(8), encoding != null ? encoding : "UTF-8");
            } catch (UnsupportedEncodingException e) {
                logger.log(Level.SEVERE, "Error while trying to decode the payload");
                return;
            }
        }

        if (payload == null) {
            logger.log(Level.SEVERE, "Payload is null, maybe content type '{0}' is not supported by this plugin. "
                    + "Please use 'application/json' or 'application/x-www-form-urlencoded'",
                    new Object[] { type });
            return;
        }

        logger.log(Level.FINE, "Got payload event: {0}", event);

        try {
            GitHub gh = GitHub.connectAnonymously();

            if ("issue_comment".equals(event)) {
                IssueComment issueComment = getIssueComment(payload, gh);
                GHIssueState state = issueComment.getIssue().getState();
                if (state == GHIssueState.CLOSED) {
                    logger.log(Level.INFO, "Skip comment on closed PR");
                    return;
                }

                String repoName = issueComment.getRepository().getFullName();

                logger.log(Level.INFO, "Checking issue comment ''{0}'' for repo {1}", new Object[] { issueComment.getComment(), repoName });

                for (GhprbWebHook webHook : getWebHooks()) {
                    try {
                        if (webHook.matchRepo(repoName) && webHook.checkSignature(body, signature)) {
                            IssueComment authedComment = getIssueComment(payload, webHook.getGitHub());
                            webHook.handleComment(authedComment);
                        }
                    } catch (Exception e) {
                        logger.log(Level.SEVERE, "Unable to process web hook for: " + webHook.getProjectName(), e);
                    }
                }

            } else if ("pull_request".equals(event)) {
                PullRequest pr = getPullRequest(payload, gh);
                String repoName = pr.getRepository().getFullName();

                logger.log(Level.INFO, "Checking PR #{1} for {0}", new Object[] { repoName, pr.getNumber() });

                Boolean filesLoaded = false;
                List<File> allFiles = new ArrayList();
                for (GhprbWebHook webHook : getWebHooks()) {
                    try {
                        if (webHook.matchRepo(repoName) && webHook.checkSignature(body, signature)) {
                            PullRequest authedPr = getPullRequest(payload, webHook.getGitHub());
                            AbstractProject<?, ?> job = webHook.getProject();
                            if (filesLoaded == false) {
                              try {
                                allFiles = getPRFiles(authedPr, webHook);
                                filesLoaded = true;
                              } catch (Exception e) {
                                  logger.log(Level.SEVERE, "Unable to fetch PR files for " + webHook.getProjectName(), e);
                              }
                            }
                            if (job.getProperty(GithubProjectProperty.class) == null
                                || (job.getProperty(GithubProjectProperty.class) != null
                                    && (job.getProperty(GithubProjectProperty.class).getRepositoryPath() == null
                                    || job.getProperty(GithubProjectProperty.class).getRepositoryPath() == "")
                                )
                                || checkCommitPaths(job.getProperty(GithubProjectProperty.class)
                                    .getRepositoryPath(), allFiles)) {
                                logger.log(Level.INFO, "Matched PR commits paths for : " + webHook.getProjectName());
                                webHook.handlePR(authedPr);
                            }
                        }
                    } catch (Exception e) {
                        logger.log(Level.SEVERE, "Unable to process web hook for: " + webHook.getProjectName(), e);
                    }
                }
            } else {
                logger.log(Level.WARNING, "Request not known");
            }

        } catch (IOException e) {
            logger.log(Level.SEVERE, "Unable to connect to GitHub anonymously", e);
        }
    }

    private List<File> getPRFiles(PullRequest pullRequest, GhprbWebHook webHook)
        throws IOException
    {
      GHRepository ghRepo = webHook.getGHRepository();
      GHPullRequest pr = pullRequest.getPullRequest();
      List<GHPullRequestCommitDetail> commits = pr.listCommits().asList();
      ArrayList<File> allFiles = new ArrayList();
      for (int i = 0, size = commits.size(); i < size; i++) {
          GHPullRequestCommitDetail commitDetail = commits.get(i);
          GHCommit ghCommit = ghRepo.getCommit(commitDetail.getSha());
          List<File> files = ghCommit.getFiles();
          allFiles.addAll(files);
      }

      return allFiles;
    }

    private boolean checkCommitPaths(String repositoryPath, List<File> allFiles)
    {
        for (int j = 0, sizeFile = allFiles.size(); j < sizeFile; j++) {
          File file = allFiles.get(j);
          if (file.getFileName().startsWith(repositoryPath)) {
            return true;
          }
        }

        return false;
    }

    private PullRequest getPullRequest(String payload, GitHub gh) throws IOException {
        PullRequest pr = gh.parseEventPayload(new StringReader(payload), PullRequest.class);
        return pr;
    }

    private IssueComment getIssueComment(String payload, GitHub gh) throws IOException {
        IssueComment issueComment = gh.parseEventPayload(new StringReader(payload), IssueComment.class);
        return issueComment;
    }

    private String extractRequestBody(StaplerRequest req) {
        String body = null;
        BufferedReader br = null;
        try {
            br = req.getReader();
            body = IOUtils.toString(br);
        } catch (IOException e) {
            body = null;
        } finally {
            IOUtils.closeQuietly(br);
        }
        return body;
    }


    private Set<GhprbWebHook> getWebHooks() {
        final Set<GhprbWebHook> webHooks = new HashSet<GhprbWebHook>();

        // We need this to get access to list of repositories
        Authentication old = SecurityContextHolder.getContext().getAuthentication();
        SecurityContextHolder.getContext().setAuthentication(ACL.SYSTEM);

        try {
            for (AbstractProject<?, ?> job : Jenkins.getInstance().getAllItems(AbstractProject.class)) {
                GhprbTrigger trigger = job.getTrigger(GhprbTrigger.class);
                if (trigger == null || trigger.getWebHook() == null) {
                    continue;
                }
                webHooks.add(trigger.getWebHook());
            }
        } finally {
            SecurityContextHolder.getContext().setAuthentication(old);
        }

        if (webHooks.size() == 0) {
            logger.log(Level.WARNING, "No projects found using GitHub pull request trigger");
        }

        return webHooks;
    }

    @Extension
    public static class GhprbRootActionCrumbExclusion extends CrumbExclusion {

        @Override
        public boolean process(HttpServletRequest req, HttpServletResponse resp, FilterChain chain) throws IOException, ServletException {
            String pathInfo = req.getPathInfo();
            if (pathInfo != null && pathInfo.equals(getExclusionPath())) {
                chain.doFilter(req, resp);
                return true;
            }
            return false;
        }

        public String getExclusionPath() {
            return "/" + URL + "/";
        }
    }
}
