# Python Webhook Function for Code Engine

## Overview

This is a simple Python webhook function that can be deployed to IBM Cloud Code Engine. It listens for incoming Webhook events from Github actions. When a new event is received, it will update an existing [application deployment](https://github.com/cloud-design-dev/simple-flask-ce-template) in Code Engine with the latest container image.

![Code Engine Webhook Function](https://images.gh40-dev.systems/ce-fn-gh-hook.png)

