FROM ubuntu


COPY sidecar-injector-webhook /sidecar-injector-webhook

EXPOSE 8443

CMD ["/sidecar-injector-webhook"]
