import azure.cognitiveservices.speech as speechsdk
import threading

# Set up the Speech to Text API
speech_key, service_region = "e858dc86ee5844d3a34bea0fedfcc497", "eastus"
speech_config = speechsdk.SpeechConfig(
    subscription=speech_key, region=service_region)

# Start a continuous recognition session
speech_recognizer = speechsdk.SpeechRecognizer(speech_config=speech_config)
print("Say something...")
speech_synthesizer = speechsdk.SpeechSynthesizer(speech_config=speech_config)
# Define a function to start listening and convert speech to text

def start_listening():
    result = speech_recognizer.recognize_once()
    print("Recognized: {}".format(result.text))

# Start a separate thread to continuously check the transcript
def check_transcript():
    while True:
        result = speech_recognizer.recognize_once()
        transcript = result.text

        # Check the transcript for the trigger word
        if "Hello" in transcript:
            # Start listening for additional input
            additional_input = start_listening()
            speech_synthesizer.speak_text_async("start recognizing").get()

        if "Goodbye" in transcript:
            speech_synthesizer.speak_text_async("stop recognizing").get()
            print("Script Closed")
            quit()


threading.Thread(target=check_transcript).start()
