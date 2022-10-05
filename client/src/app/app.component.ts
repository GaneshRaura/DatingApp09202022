import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})

export class AppComponent implements OnInit {
  title = 'Dating App';
  test1 = "This is my test"
  users: any;

constructor(private http: HttpClient) {}
  ngOnInit() {
       this.getUsers(); 
    /*throw new Error('Method not implemented.');*/
  }
  getUsers(){
    this.http.get('https://localhost:5001/api/users').subscribe(response => {this.users = response;}, error => {console.log(error);});
  }
}