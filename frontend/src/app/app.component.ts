import { Component, signal } from '@angular/core';
import { RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-root',
  standalone: true,
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css'], // ispravljeno: styleUrls umesto styleUrl
  imports: [RouterOutlet]             // koristi RouterOutlet umesto AppRoutingModule
})
export class AppComponent {
  protected readonly title = signal('frontend');
}
