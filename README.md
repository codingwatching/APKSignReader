# APKSignReader
A tool to read APK Signatures and format it to other style (Base64, C++, etc)

# Android version
Android version supports signature scheme v1-v4, it works by using `getPackageInfo` to get app signature.

# Windows version
Windows version only support signature scheme v1, it works by opening the `.apk` as zip and find .DSA/.RSA file in the zip entry.
