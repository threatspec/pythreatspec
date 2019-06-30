FROM python:2.7

WORKDIR /usr/src/app
COPY . .

RUN uname -r

#Update apt-get and add nodejs
RUN apt-get update && apt-get -y install nodejs

# Install apt-transport-https for Yarn repository
RUN apt-get install apt-transport-https -y

#Yarn install
# Add Yarn repository
RUN curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
RUN echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list

# Update
RUN apt-get update -y

# Install Yarn
RUN apt-get install yarn -y

#Verify python
RUN python --version

#Verify nodejs
RUN apt-get update && apt-get install -y curl
RUN curl -sL https://deb.nodesource.com/setup_8.x | bash -
RUN apt-get update && apt-get install -y nodejs

RUN npm install npm@latest -g


#Verify yarn 
#RUN yarn --version

#Install mermaid
RUN yarn add mermaid

#At this point we should have everything we need
#-----------------------------------------------
#Switch to tutorial directory
RUN cd /usr/src/app/tutorial && ls
RUN python setup.py install

#Tutorial Setup
#RUN ["/bin/bash", "-c", "virtualenv venv"]

ENTRYPOINT ["/bin/bash"]
CMD ["cd","/usr/src/app/examples/"]

RUN /usr/src/app/examples/run_codeparser_step.sh simple_web