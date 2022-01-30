FROM python:3

RUN pip3 install ruamel.yaml


RUN git clone https://github.com/SigmaHQ/sigma.git

RUN git clone git@github.com:refractionPOINT/sigma-limacharlie.git -b rules