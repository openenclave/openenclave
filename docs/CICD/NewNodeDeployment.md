Open Enclave SDK CI/CD Node Deployment Guide
============================================

1. On all newly deployed systems intended to be connected to Jenkins, run:

```bash
sudo apt-get update; \
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"; \
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -; \
sudo apt-get update; \
sudo apt-get -y install docker-ce default-jre git apt-transport-https ca-certificates curl software-properties-common; \
sudo docker run hello-world; \
sudo useradd -d /home/jenkins -m jenkins; \
sudo useradd -d /home/oeadmin -m oeadmin; \
sudo usermod -G sudo oeadmin; \
sudo usermod -aG docker jenkins; \
sudo mkdir -p /home/jenkins/.ssh/; \
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDGOdxob4Miv+LmgkUoAoTp0fxnGb6j22c95CkfBr2Hb9GqZm5DqA0yRL9fDCy2QFfCSNBOd9U/4LGb6YvFZurw+wnreLIl6N2ZDb5uFZmw6ES1l+SoWoF6pkQ3sMNNcVcZqMA/t94x7IUD7Qb5fU1u54bKGwQtVoNzuyzqoON0fT1eEZeCVN6TNfxg4J0fUH6abd5k2IOv4J9A0HI7qFt4WTAYogVr8QLAkJSKC0udvs6o2RyUkstJD9T2Ofx53Zg9nolqf5AffEI5aIKkbLnRgPHerwMXyamLh9KtJvsUL5HZqK6Gbz9RDFpQnaB4nlvio6WR8s6PPLk7TvmRXFRYigzoA2deLVyY8Y+uyxDmU/K9DMeseDKWTGfBOj92mhexWA3xHRViM0ULxwRmSS/PoFFAag5qUui/vf5kYLGtWn0Iacvvs2ZJHY2+Hy6LXP5PkKzTnqu+yPw/A8zNzieppRYIE87Am1zF5BLVT9FTm3vtG8JGsA24kSeqsjEGdwjVWRpVM1+QywWd1vucDwdsQBKeRNofDEjbIK3WqYA3w4hzRo6ejvR5tVaEgtM7puvZxu9FGEWoF8OSlVth43XFfWD+6sjIBizmYmnI6qtm2Kc6Vb3odZtgCYPHI8NAVEJe9X92pnCtAbAGZTvnsmaqUBR1VoNYwqrJiYjPcVx9/Q== jenkins@acc1" | sudo tee -a /home/jenkins/.ssh/authorized_keys; \
sudo chown -R jenkins /home/jenkins/.ssh
```

2. Set the oeadmin user password:

```bash
sudo passwd oeadmin
```

Note: The password for oeadmin can be found in the OE-Jenkins Azure Key Vault.

3. If the system supports SGX, follow [the instructions here](https://github.com/Microsoft/openenclave/blob/master/docs/GettingStartedDocs/SGX1FLCGettingStarted.md) to finalize the deployment of the system.

