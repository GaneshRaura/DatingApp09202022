import { AccountService } from './_services/account.service';
import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { User } from './_models/user';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})

export class AppComponent implements OnInit {

  title = 'Dating App';
  test1 = "This is my test"
  users: any;

constructor(private accountService: AccountService ) {}
  ngOnInit() {
   
       this.setCurrentUser();
    /*throw new Error('Method not implemented.');*/
  }

  setCurrentUser(){
    const user: User = JSON.parse(localStorage.getItem('user'))
  }

}
