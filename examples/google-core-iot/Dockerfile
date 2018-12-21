FROM python:3.7-slim-stretch
WORKDIR /usr/src/app

# Declare required arguments
ENV DEVICE_ID=
ENV REGISTRY_ID=
ENV CLOUD_REGION=
ENV PROJECT_ID=

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential libssl-dev libffi-dev libltdl-dev wget && \
    apt-get clean

RUN wget https://raw.githubusercontent.com/GoogleCloudPlatform/python-docs-samples/master/iot/api-client/mqtt_example/cloudiot_mqtt_example.py && \
    wget https://raw.githubusercontent.com/GoogleCloudPlatform/python-docs-samples/master/iot/api-client/mqtt_example/requirements.txt && \
    wget https://pki.google.com/roots.pem
RUN pip install --no-cache-dir -r requirements.txt

CMD python cloudiot_mqtt_example.py \
    --registry_id=${REGISTRY_ID} \
    --cloud_region=${CLOUD_REGION} \
    --project_id=${PROJECT_ID} \
    --device_id=${DEVICE_ID} \
    --algorithm=ES256 \
    --private_key_file=/opt/wott/cert/client.key \
    --ca_certs=roots.pem
