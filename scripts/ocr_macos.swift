#!/usr/bin/env swift
// Source: https://evanhahn.com/mac-ocr-script/
// macOS OCR helper using the Vision framework.
// Compiled once by scrape_malicious_domains.rb; not run directly.
//
// Usage: ocr_macos /path/to/image.png
// Output: recognised text lines on stdout; errors on stderr.
//
// Requires macOS 10.15+ (VNRecognizeTextRequest).

import Foundation
import Vision

let args = CommandLine.arguments
guard args.count == 2 else {
  fputs("usage: ocr_macos /path/to/image\n", stderr)
  exit(1)
}

let imageURL = URL(fileURLWithPath: args[1])

guard FileManager.default.fileExists(atPath: args[1]) else {
  fputs("error: file not found: \(args[1])\n", stderr)
  exit(1)
}

let requestHandler = VNImageRequestHandler(url: imageURL, options: [:])
let request = VNRecognizeTextRequest()
request.recognitionLevel = .accurate
request.usesLanguageCorrection = true
// psm-11 equivalent: find as much text as possible in the image
request.minimumTextHeight = 0.01

do {
  try requestHandler.perform([request])
} catch {
  fputs("error: \(error.localizedDescription)\n", stderr)
  exit(1)
}

guard let observations = request.results, !observations.isEmpty else {
  exit(0)
}

for observation in observations {
  if let candidate = observation.topCandidates(1).first {
    print(candidate.string)
  }
}
