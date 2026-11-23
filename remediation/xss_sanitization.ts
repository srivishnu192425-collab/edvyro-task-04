/**
 * Remediation Fix: Safe Input Handling & DOM XSS Prevention
 * Target: SEC-05 (DOM-based Cross-Site Scripting)
 * Tech Stack: Angular / TypeScript / DOMPurify
 */

import { Component, OnInit, SecurityContext } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import * as DOMPurify from 'dompurify';

@Component({
  selector: 'app-search-result',
  template: `
    <div class="search-container">
      <h2>Search Results</h2>

      <!-- VULNERABLE TEMPLATE PATTERN:
           <div [innerHTML]="sanitizer.bypassSecurityTrustHtml(rawQuery)"></div>
           Bypassing Angular's built-in sanitizer allows arbitrary script execution!
      -->

      <!-- SECURE PATTERN 1: Standard Angular Template Binding (Recommended)
           Angular automatically contextualizes and escapes special characters in {{ }}
      -->
      <p class="search-summary">
        You searched for: <strong>{{ cleanSearchTerm }}</strong>
      </p>

      <!-- SECURE PATTERN 2: Explicit DOMPurify Sanitization when HTML rendering is strictly necessary -->
      <div *ngIf="safeHtmlSnippet" [innerHTML]="safeHtmlSnippet"></div>
    </div>
  `
})
export class SearchResultComponent implements OnInit {
  cleanSearchTerm: string = '';
  safeHtmlSnippet: SafeHtml | null = null;

  constructor(
    private route: ActivatedRoute,
    private sanitizer: DomSanitizer
  ) {}

  ngOnInit(): void {
    this.route.queryParams.subscribe(params => {
      const userQuery = params['q'] || '';

      // FIX 1: Treat user input as plain text data, not executable HTML
      this.cleanSearchTerm = userQuery;

      // FIX 2: If HTML markup is mandatory, sanitize strictly with DOMPurify
      // Strip all script tags, object tags, javascript: URIs, and dangerous attributes
      const sanitizedHtml = DOMPurify.sanitize(userQuery, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'span'],
        ALLOWED_ATTR: ['class']
      });

      // Wrap in Angular Sanitizer safely
      this.safeHtmlSnippet = this.sanitizer.sanitize(SecurityContext.HTML, sanitizedHtml);
    });
  }
}
