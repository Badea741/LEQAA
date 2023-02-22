import React from "react";
import { useDispatch } from "react-redux";
import { Link, useLocation } from "react-router-dom";
import { useAuth } from "../../Custom/useAuth";
import { getMsgs } from "../../redux/chatSlice";
import RadiusImg from "../RadiusImg/RadiusImg";
import "./Card.css";

function Card(props) {
  const cardInformation = props.card;
  const auth = useAuth()
  const {pathname} = useLocation()
  const dispatch = useDispatch()
  const toSomeone = cardInformation?.to == auth.user.user?.userName ? cardInformation?.from : cardInformation?.to
  const handleClick = () =>{
    console.log(pathname);
    console.log(toSomeone);
    if (pathname == '/chat') {
      dispatch(getMsgs(toSomeone))
    }
  }

  return (
    <div className="card" onClick={() => handleClick()}>

      {cardInformation?.existingNumbers ||
      cardInformation?.msg ||
      cardInformation?.memberName ||
      cardInformation?.channelName ? (
        <RadiusImg size="40px" />
      ) : null}

      <div className="content">

        <div className="meeting-created-by">
          {cardInformation?.meetingCreatedBy}
        </div>

        <div className="meeting">
          <div className="meeting-name">{cardInformation?.meetingName}</div>
          {cardInformation?.meetingCreatedTime && (
            <button className="btn">
              {cardInformation?.meetingCreatedBy.includes("scheduled")
                ? "notify me"
                : "join"}
            </button>
          )}
        </div>

        <div className="existing-numbers">
          {cardInformation?.existingNumbers}
        </div>

        <div className="meeting-created-time">
          {cardInformation?.meetingCreatedTime}
        </div>
        
        {cardInformation?.existingNumbers && (
          <button className="join btn">join</button>
        )}
{/* ///////////////////////////////////////////////////////////////////////////////// */}
        <div className="post">
          <div className="post-created-by">{cardInformation?.postCreatedBy}</div>
          <div className="post-created-time">
            {cardInformation?.postCreatedTime}
          </div>
        </div>
        <div className="post-desc">{cardInformation?.postDesc}</div>
{/* //////////////////////////////////////////////////////////////////////////////////////////// */}
        <div className="msg-by">{cardInformation?.to == auth.user.user?.userName ? cardInformation?.from : cardInformation?.to}</div>
        <div className="msg">{cardInformation?.msg}</div>
{/* ///////////////////////////////////////////////////////////////////////////////////////////// */}
        <div className="channel-name">{cardInformation?.channelName}</div>
        <div className="channel-status">{cardInformation?.channelStatus}</div>
{/* ////////////////////////////////////////////////////////////////////////////////////////////////// */}
        <div className="member">
          <div className="member-name">{cardInformation?.memberName}</div>
          {cardInformation?.memberName && <button className="btn">Follow</button>}
        </div>
        <div className="member-bio">{cardInformation?.memberBio}</div>
{/* /////////////////////////////////////////////////////////////////////////////////////////////////// */}
        <div className="announcement">
              <div className="announcement-desc">{cardInformation?.announcementDesc}</div>
              <div className="announcement-created-time">{cardInformation?.announcementCreatedTime}</div>
        </div>
      </div>
    </div>
  );
}

export default Card;
