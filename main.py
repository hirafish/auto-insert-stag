# coding: UTF-8
from burp import IBurpExtender
from burp import IHttpListener
import re
import json

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Extenderの登録を行う
        callbacks.registerHttpListener(self)
        callbacks.setExtensionName("Insert <s> json")

        # ヘルパをメンバ変数に格納しておく
        self._helpers = callbacks.getHelpers()

    def parseResponse(self, response, responseBodyOffset):
        parseReponseList = []
        for txt in response[responseBodyOffset:]:
            parseReponseList.append(txt)
            if len(parseReponseList) >= 2:
                if parseReponseList[-2:] == [':', '"']:
                    parseReponseList.append("<s>")

        parseReponseStr = "".join(parseReponseList)
        parsedResponseBody = response[:responseBodyOffset] + parseReponseStr

        return "".join(parsedResponseBody)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # リクエストの場合は処理を打ち切る
        if messageIsRequest:
            return

        responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
        responseRaw = messageInfo.getResponse()
        responseBodyOffset = responseInfo.getBodyOffset()
        response = responseRaw.tostring()

        print(responseInfo)
        print(response)

        try:
            json.loads(response[responseBodyOffset:])
            parsedResponseBody = self.parseResponse(response,responseBodyOffset)
            print(">========================================")
            print(parsedResponseBody)
            print("========================================<")
            messageInfo.setResponse(self._helpers.stringToBytes(parsedResponseBody))
        except:
            pass
