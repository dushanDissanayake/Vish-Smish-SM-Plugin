import azure.cognitiveservices.speech as speechsdk
import re
import re
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import sent_tokenize, word_tokenize
from nltk.tag import pos_tag




def recognize_from_audiofile():
    # This example requires environment variables named "SPEECH_KEY" and "SPEECH_REGION"
    SPEECH_KEY, SPEECH_REGION = "e858dc86ee5844d3a34bea0fedfcc497", "eastus"
    speech_config = speechsdk.SpeechConfig(
        subscription=SPEECH_KEY, region=SPEECH_REGION)
    speech_config.speech_recognition_language = "en-US"

    audio_config = speechsdk.audio.AudioConfig(
        filename="CreditCardScamVoicemail.wav")
    speech_recognizer = speechsdk.SpeechRecognizer(
        speech_config=speech_config, audio_config=audio_config)

    recognized_text = ""

    print("Recognizing...")

    while True:
        speech_recognition_result = speech_recognizer.recognize_once()

        if speech_recognition_result.reason == speechsdk.ResultReason.RecognizedSpeech:
            print("Recognized: {}".format(speech_recognition_result.text))
            recognized_text += speech_recognition_result.text

        print(recognized_text)
        return recognized_text
        # print(recognized_text)



def recognize_from_audiofile():
    # This example requires environment variables named "SPEECH_KEY" and "SPEECH_REGION"
    SPEECH_KEY, SPEECH_REGION = "e858dc86ee5844d3a34bea0fedfcc497", "eastus"
    speech_config = speechsdk.SpeechConfig(
        subscription=SPEECH_KEY, region=SPEECH_REGION)
    speech_config.speech_recognition_language = "en-US"

    audio_config = speechsdk.audio.AudioConfig(
        filename="CreditCardScamVoicemail.wav")
    speech_recognizer = speechsdk.SpeechRecognizer(
        speech_config=speech_config, audio_config=audio_config)

    recognized_text = ""

    print("Recognizing...")

    while True:
        speech_recognition_result = speech_recognizer.recognize_once()

        if speech_recognition_result.reason == speechsdk.ResultReason.RecognizedSpeech:
            print("Recognized: {}".format(speech_recognition_result.text))
            recognized_text += speech_recognition_result.text

        print(recognized_text)
        #return recognized_text



def preprocess_text():
    recognized_text = "Hello, this is Alice calling from the underwriting department regarding your Discover credit card account. Based on your recent payment activity and balance, you are eligible for an interest rate reduction to as low as 1.9%. To take advantage of this limited time offer, please call card member services directly at 1-800-694-0048. Once again, that's 18 hundred 694004.8 This will be the only notice you receive and this offer is only valid for three business days. Thank you. Hello, this is Elizabeth calling from the underwriting department regarding your Capital One credit card account. Based on your recent payment activity and balance, you may be eligible for an interest rate reduction to as low as 1.9%. There is additional information I need to confirm your eligibility, so please return my call directly in the underwriting department at one 800.2586019 I'll once again 1-800-258-6019 and this will be the only notice you receive and this offers only valid for three business days. Thank you."
    print("Recognized Text: ", recognized_text)
    print("\n")

    # Lowercase the text
    recognized_text = recognized_text.lower()

    # Remove punctuation and digits
    recognized_text = re.sub(r'[^\w\s]', '', recognized_text)

    # Tokenize the text into sentences and words
    sentences = sent_tokenize(recognized_text)
    words = [word_tokenize(sent) for sent in sentences]

    # Remove stop words
    stop_words = set(stopwords.words('english'))
    words = [[word for word in sent if word not in stop_words]
                for sent in words]

    # Perform lemmatization
    lemmatizer = WordNetLemmatizer()
    words = [[lemmatizer.lemmatize(word)
                for word in sent] for sent in words]

    # Perform POS tagging
    pos_tags = [[(word, pos) for word, pos in pos_tag(sent)]
                for sent in words]

    print(pos_tags)
    print("\n")
    
    words = [' '.join(sent) for sent in words]

    text = ' '.join(words)
    print(text)
    print("\n")

def main():
    # recognize_from_audiofile()
    preprocess_text()



if __name__ == "__main__":
    main()

# main = recognize_from_audiofile()
#     main.preprocess_text(recognized_text)
