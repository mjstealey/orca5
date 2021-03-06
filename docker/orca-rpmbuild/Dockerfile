#FROM centos:centos6.8
# Pull from ${project.version} of orca-base, since it doesn't need to change very often
FROM renci/orca-base:${project.version}-${orca.docker.jre.vendor}

# yum ant also install openjdk
#RUN yum -y install rpm-build git ant && yum clean all
RUN yum -y install rpm-build git && yum clean all

# Oracle installs the full JDK, but openjdk by default only installs the JRE
RUN if [ "${orca.docker.jre.vendor}" == "openjdk_1.8" ]; then \
		yum -y install java-1.8.0-openjdk-devel && yum clean all; \
	fi


# Install Apache Maven
ENV apache_maven_version apache-maven-3.3.9

RUN cd /opt && \
    curl "https://archive.apache.org/dist/maven/maven-3/3.3.9/binaries/${apache_maven_version}-bin.tar.gz" > ${apache_maven_version}-bin.tar.gz && \
    tar zxf ${apache_maven_version}-bin.tar.gz && \
    rm -f ${apache_maven_version}-bin.tar.gz

# Install Apache Ant
ENV apache_ant_version apache-ant-1.9.9

RUN cd /opt && \
    curl "http://archive.apache.org/dist/ant/binaries/${apache_ant_version}-bin.tar.gz" > ${apache_ant_version}-bin.tar.gz && \
    tar zxf ${apache_ant_version}-bin.tar.gz && \
    rm -f ${apache_ant_version}-bin.tar.gz

ENV ANT_HOME /opt/${apache_ant_version}

# Setup PATH variable with Maven and Ant
ENV PATH /opt/${apache_maven_version}/bin:$PATH:$ANT_HOME/bin

COPY ./docker-entrypoint.sh /

RUN chmod a+x /docker-entrypoint.sh

# COPY Orca source tree, if present (e.g. Maven on Mac will copy Orca source tree)
COPY orca /root/git/orca5

# we don't want to copy the git objects into the image,
# but the folder needs to exist in order to trick git
# into allowing us to get the commit ID
RUN mkdir -p /root/git/orca5/.git/objects/

# The Orca source must be volume mounted from the local/host machine
#  (at the `docker run` command)
#  for this entrypoint to work.
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/root/git/orca5/redhat/buildrpm.sh"]
