package org.jenkinsci.plugins.ghprb.manager.impl;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doReturn;

import java.util.HashMap;
import java.util.Map;

import com.coravy.hudson.plugins.github.GithubProjectProperty;

import hudson.matrix.MatrixBuild;
import hudson.matrix.MatrixProject;

import org.jenkinsci.plugins.ghprb.Ghprb;
import org.jenkinsci.plugins.ghprb.GhprbITBaseTestCase;
import org.jenkinsci.plugins.ghprb.GhprbTestUtil;
import org.jenkinsci.plugins.ghprb.GhprbTrigger;
import org.jenkinsci.plugins.ghprb.manager.GhprbBuildManager;
import org.jenkinsci.plugins.ghprb.manager.factory.GhprbBuildManagerFactoryUtil;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.jvnet.hudson.test.JenkinsRule;
import org.mockito.runners.MockitoJUnitRunner;

/**
 * @author mdelapenya (Manuel de la Peña)
 */
@RunWith(MockitoJUnitRunner.class)
public class GhprbDefaultBuildManagerTest extends GhprbITBaseTestCase {

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @Before
    public void setUp() throws Exception {
        // GhprbTestUtil.mockGithubUserPage();
        super.beforeTest();
    }

    @Test
    public void shouldCalculateUrlFromDefault() throws Exception {
        // GIVEN
        MatrixProject project = givenThatGhprbHasBeenTriggeredForAMatrixProject();

        // THEN
        assertThat(project.getBuilds().toArray().length).isEqualTo(1);

        MatrixBuild matrixBuild = project.getBuilds().getFirstBuild();

        GhprbBuildManager buildManager = GhprbBuildManagerFactoryUtil.getBuildManager(matrixBuild);

        assertThat(buildManager).isInstanceOf(GhprbDefaultBuildManager.class);

        assertThat(buildManager.calculateBuildUrl("defaultPublishedURL")).isEqualTo("defaultPublishedURL/" + matrixBuild.getUrl());
    }

    private MatrixProject givenThatGhprbHasBeenTriggeredForAMatrixProject() throws Exception {
        MatrixProject project = jenkinsRule.createMatrixProject("MTXPRJ");

        GhprbTrigger trigger = GhprbTestUtil.getTrigger(null);

        given(commitPointer.getSha()).willReturn("sha");
        
        Map<String, Object> config = new HashMap<String, Object>(1);
        config.put("publishedURL", "defaultPublishedURL");

        GhprbTestUtil.setupGhprbTriggerDescriptor(config);


        project.addProperty(new GithubProjectProperty("https://github.com/user/dropwizard", "/some/path"));

        given(ghPullRequest.getNumber()).willReturn(1);

        // Creating spy on ghprb, configuring repo
        Ghprb ghprb = spyCreatingGhprb(trigger, project);

        doReturn(ghprbGitHub).when(ghprb).getGitHub();

        setRepositoryHelper(ghprb);

        given(ghRepository.getPullRequest(1)).willReturn(ghPullRequest);

        // Configuring and adding Ghprb trigger
        project.addTrigger(trigger);

        // Configuring Git SCM
        project.setScm(GhprbTestUtil.provideGitSCM());

        trigger.start(project, true);

        setTriggerHelper(trigger, ghprb);

        GhprbTestUtil.triggerRunAndWait(10, trigger, project);

        return project;
    }
}