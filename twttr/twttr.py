def main():
    text = input("Input: ")
    print("Output: ", end="")
    for word in text:
        if word.lower() not in ["a", "e", "i", "o", "u"]:
            print(word, end="")
    print()
if __name__ == "__main__":
    main()

     